/*
 * Конвейер одного сообщения: разбор -> очередь -> бюджет -> обменник -> решение.
 *
 * Ответ уходит на каждом пути, включая панику: молчание неотличимо от
 * перегрузки, см. docs/inspectors.md#контракт.
 *
 * Единственный поход наружу -- чтение заголовков из обменника. Он и есть цена
 * этого инспектора: cookie сессии инлайном не едет, а инлайн-драйвер горячий
 * путь не вызывает.
 */

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
	"github.com/exemt/placitum-auth/internal/dataset"
	"github.com/exemt/placitum-auth/internal/decide"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/queue"
	"github.com/exemt/placitum-auth/internal/store"
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
	// lists -- запись в активный список: подглядывание входа приложения
	// рождает записи доверенных сессий на фазе ответа маршрута входа, правила
	// событий пишут адрес клиента, его подсеть или систему.
	lists *dataset.Publisher
	// resolver -- кодер гео: анонсы и состав системы, когда правило события
	// пишет не адрес (net, net_all, asn). nil -- кодера нет: такие строки
	// отвечают error, адрес пишется как всегда.
	resolver *netinfo.Resolver
	pool     *queue.Pool
	// forms -- форма входа для deny телом ответа; nil без адреса auth-http,
	// и тогда inline-профили отвечают редиректом.
	forms *formFetcher
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

	/*
	 * Незнакомая версия схемы -- расхождение модуля и инспектора: проверки не
	 * было, и распорядиться этим должен маршрут. Прежний deny запирал вход за
	 * чужую ошибку развёртывания.
	 */
	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	/*
	 * Калитка живёт в фазе запроса: redirect в фазе ответа запрещён
	 * контрактом, а заголовки запроса к тому времени уже отправлены. Фаза
	 * ответа -- только подглядывание входа приложения (провайдер app), и
	 * решает это профиль в inspect. Кадры -- error: инспектор в наборе кадров
	 * это ошибка конфигурации, увидеть её надо сразу, но выбирать за маршрут
	 * между пропуском и отказом калитке нечем.
	 */
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
		/*
		 * Сброшенный запрос -- не проверенный запрос. Раньше здесь стоял allow с
		 * доводом «под нагрузкой не уводить всех на форму»: довод верный, но это
		 * решение маршрута, а не инспектора, и теперь его говорит
		 * waf_exception … inspector pass.
		 */
		reply := protocol.ShedReply(t.Req, shed)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds())
		h.send(t.Reply, reply, t.Req, audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	reply, det := h.inspect(ctx, t.Req)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(ctx context.Context, req *protocol.Request) (
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

	/*
	 * В обменник идём только когда решение от него зависит. Профиля нет либо
	 * режим off -- ответ известен и без заголовков, а лишний round-trip
	 * внутри бюджета волны стоит дороже проверки двух полей.
	 */
	if profile != nil && profile.Mode != config.ModeOff {
		pairs, args, why, fault := store.Pair(ctx, h.store, req.Store.Headers, req.Store.Args)

		/*
		 * Заголовки лежали, а обменник их не отдал. "Сессии не видно" здесь
		 * означало бы "клиент пришёл без cookie", и лестница увела бы на форму
		 * каждого вошедшего: отказ обслуживания под видом обычного решения.
		 */
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
	}

	res := decide.Check(in, h.cfg.Key, h.sessions)

	/*
	 * Форма телом ответа: страница в обменник, адрес -- в реплай. Не вышло --
	 * редирект на форму, как у обычного профиля: билет клиенту уже выписан,
	 * и лестница заполнила запасной адрес заранее.
	 */
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

	// Событие лестницы -- правила профиля: просьбы соседям и маршруту,
	// записи адреса в набор. Пассивный вызов и наблюдение их не глушат:
	// правило -- решение оператора, а не вердикт.
	var fired []protocol.Action

	if profile != nil && profile.Mode != config.ModeOff {
		var err error

		fired, err = h.fireEvent(ctx, profile, res, req.Conn.ClientIP)

		/*
		 * Правило требует кодер, а кодер молчит: запись в набор не
		 * состоялась. Молча пропустить нельзя -- бан, которого не было,
		 * выглядит как бан, -- поэтому error, как у остальных отправителей;
		 * что делать с запросом, решает waf_exception маршрута.
		 */
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

		// Билет едет и на отказ: форма телом ответа ставит его так же, как
		// редирект, -- иначе POST входа придёт без nonce.
		reply.Cookies = res.Cookies
	}

	// Чью сессию увидели -- при любом вердикте: это запись для аудита.
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

/*
 * fireEvent -- правила события профиля. Просьбы возвращаются и уезжают в
 * ответе этого же запроса; запись в набор -- адрес клиента, его подсеть или
 * система (lists.go) -- публикуется сразу, на каждом срабатывании. События
 * калитки -- состояния: authenticated, anonymous, invalid и forbidden
 * проверяются на каждом запросе. Памяти «уже записано» здесь нет намеренно:
 * повторный add у keeper продлевает срок, а если запись должна прекратить
 * повторы -- набор ставят перед калиткой, и записанный до неё не доходит.
 *
 * Ошибка -- кодер нужен строке и молчит; остальные строки при этом пишутся.
 */
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

// askOf -- просьба соседу из правила, форма провода.
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

	// Срок и исход архива -- только у archive с set on; ноль в YAML значит
	// "как на маршруте", пустой исход -- "любой".
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
