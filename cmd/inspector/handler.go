package main

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-auth/internal/audit"
	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/decide"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/overload"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/queue"
	"github.com/exemt/placitum-auth/internal/store"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	codeUnsupportedVersion = "AUTH_UNSUPPORTED_VERSION"
	codeMalformed          = "AUTH_MALFORMED_REQUEST"
	codeInternalError      = "AUTH_INTERNAL_ERROR"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	profiles *config.Store
	store    *store.Redis
	sessions *livelist.Mirror
	lists    *dataset.Publisher
	resolver *netinfo.Resolver
	pool     *queue.Pool
	forms    *formFetcher
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, codeMalformed), nil,
			audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Phase != protocol.PhaseRequest && req.Phase != protocol.PhaseResponse {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodeWrongPhase), req,
			audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		}

		asks := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds(),
			"asks", asks)
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	reply, det := h.inspect(ctx, t.Req, t.Fill)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(ctx context.Context, req *protocol.Request, fill int) (
	*protocol.Reply, audit.Details) {

	if req.Phase == protocol.PhaseResponse {
		return h.observe(ctx, req)
	}

	start := time.Now()

	snap := h.profiles.Current()
	profile, _ := snap.Profile(req.Route.Profile)

	in := decide.Input{
		Profile:  profile,
		Ask:      req.Route.Profile,
		Method:   req.HTTP.Method,
		URI:      req.HTTP.URI,
		ClientIP: req.Conn.ClientIP,
		Prior:    req.Prior,
		Now:      time.Now(),
	}

	if profile != nil && profile.Mode != config.ModeOff {
		pairs, args, why, fault := store.Pair(ctx, h.store, req.Store.Headers, req.Store.Args)

		if fault {
			h.log.Error("store fetch failed", "rid", req.RID,
				"profile", profile.Name, "reason", why)

			return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
				Engine: map[string]any{"profile": profile.Name, "store": why},
			}
		}

		in.Headers = pairs
		in.Args = args
		in.StoreUnavailable = why
		in.Cookie = store.Cookie(pairs, profile.Src.SessionCookie())
		in.UserAgent = store.Value(pairs, "user-agent")
		in.Accept = store.Value(pairs, "accept")
		in.SecFetchDest = store.Value(pairs, "sec-fetch-dest")
		in.UpgradeInsecure = store.Value(pairs, "upgrade-insecure-requests") == "1"
	}

	res := decide.Check(in, h.cfg.Key, h.sessions)

	var rewrite *protocol.Rewrite

	if res.Inline {
		rw, err := h.inlineForm(ctx, req, profile, res, in.UserAgent)
		if err != nil {
			h.log.Warn("inline form unavailable, redirecting instead",
				"rid", req.RID, "profile", profile.Name, "error", err.Error())

			res.Verdict = protocol.VerdictRedirect
			res.Response = ""
			res.Inline = false
			res.Engine["inline_fallback"] = err.Error()
		} else {
			rewrite = rw
		}
	}

	var fired []protocol.Action

	if profile != nil && profile.Mode != config.ModeOff {
		var err error

		fired, err = h.fireEvent(ctx, profile, res, req.Conn.ClientIP)

		if err == nil {
			var more []protocol.Action

			more, err = h.fireOverload(ctx, profile, fill, false, req.Conn.ClientIP)
			fired = append(fired, more...)
		}

		if err != nil {
			h.log.Error("geo unavailable for a list write", "rid", req.RID,
				"profile", profile.Name, "event", res.Event, "error", err.Error())

			return protocol.ErrorReply(req, decide.CodeGeoUnavailable), audit.Details{
				Engine: map[string]any{"profile": profile.Name, "event": res.Event, "geo": err.Error()},
			}
		}
	}

	elapsed := time.Since(start)

	reply := toReply(req, res)
	reply.Rewrite = rewrite
	reply.Actions = append(reply.Actions, fired...)

	if res.Code == decide.CodeUnknownProfile {
		h.log.Error("unknown profile",
			"rid", req.RID,
			"profile", req.Route.Profile,
			"client_ip", req.Conn.ClientIP,
		)
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"profile", req.Route.Profile,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"verdict", reply.Verdict,
		"reason", res.Code,
		"sub", subjectOf(res),
	)

	return reply, audit.Details{
		EngineMS: float64(elapsed.Microseconds()) / 1000,
		Findings: res.Findings,
		Engine:   res.Engine,
	}
}

func toReply(req *protocol.Request, res decide.Result) *protocol.Reply {
	reply := protocol.NewReply(req, res.Verdict)

	if res.Code != "" {
		reply.Reason = &protocol.Reason{Code: res.Code}
	}

	switch res.Verdict {
	case protocol.VerdictAllow:
		for name, value := range res.Headers {
			reply.SetHeader(name, value)
		}

	case protocol.VerdictRedirect:
		reply.Redirect = &protocol.RedirectRef{
			URL:    res.RedirectURL,
			Status: res.RedirectStatus,
		}
		reply.Cookies = res.Cookies

	case protocol.VerdictDeny:
		if res.Response != "" {
			reply.Response = &protocol.ResponseRef{Name: res.Response}
		}

		reply.Cookies = res.Cookies
	}

	reply.Sessions = res.Sessions

	return reply
}

func subjectOf(res decide.Result) string {
	if res.Session == nil {
		return ""
	}

	return res.Session.Sub
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)
		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject != "" {
		h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError), nil,
			audit.Details{})
	}
}

func (h *handler) fireEvent(ctx context.Context, p *config.Profile, res decide.Result,
	clientIP string) ([]protocol.Action, error) {

	if res.Event == "" {
		return nil, nil
	}

	rules := p.RulesFor(res.Event)

	if len(rules) == 0 {
		return nil, nil
	}

	var (
		actions []protocol.Action
		failed  error
	)

	for _, r := range rules {
		if r.Do != "" {
			actions = append(actions, askOf(r))

			continue
		}

		if clientIP == "" || h.lists == nil {
			continue
		}

		reason := r.Code

		if reason == "" {
			reason = "AUTH_" + strings.ToUpper(res.Event)
		}

		if err := writeRule(ctx, h.resolver, h.lists, h.log, r, clientIP, reason); err != nil && failed == nil {
			failed = err
		}
	}

	return actions, failed
}

func askOf(r config.EventRule) protocol.Action {
	out := protocol.Action{
		To:      r.To,
		Do:      r.Do,
		Apply:   r.Axis(),
		Phase:   r.Phase,
		Code:    r.Code,
		Counter: r.Counter,
		Marker:  r.Marker,
		Group:   r.Group,
		Set:     r.Set,
		Headers: r.Headers,
		Args:    r.Args,
		Body:    r.Body,
	}

	if r.Do == protocol.DoArchive && r.Set == "on" {
		if seconds := int64(r.TTL.D().Seconds()); seconds > 0 {
			out.TTL = &seconds
		}

		if len(r.When) > 0 {
			when, _ := protocol.CheckArchiveWhen(r.When)
			out.When = when
		}
	}

	if r.Delta != nil {
		out.Delta = *r.Delta
	}

	if r.Value != nil {
		out.Value = *r.Value
	}

	return out
}

func (h *handler) fireOverload(ctx context.Context, p *config.Profile, fill int, shed bool,
	clientIP string) ([]protocol.Action, error) {

	var (
		actions []protocol.Action
		failed  error
	)

	for _, r := range p.RulesFor(config.OnOverload) {
		if !overload.Fires(overload.At(r.At), fill, shed) {
			continue
		}

		if r.Do != "" {
			actions = append(actions, askOf(r))

			continue
		}

		if clientIP == "" || h.lists == nil {
			continue
		}

		reason := r.Code

		if reason == "" {
			reason = queue.ReasonQueueLimit
		}

		if err := writeRule(ctx, h.resolver, h.lists, h.log, r, clientIP, reason); err != nil && failed == nil {
			failed = err
		}
	}

	return actions, failed
}

func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) int {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return 0
	}

	profile, _ := h.profiles.Current().Profile(t.Req.Route.Profile)
	if profile == nil || profile.Mode == config.ModeOff {
		return 0
	}

	actions, err := h.fireOverload(context.Background(), profile, t.Fill, true, t.Req.Conn.ClientIP)
	if err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", profile.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	if len(actions) != 0 {
		reply.Actions = actions
	}

	return len(actions)
}
