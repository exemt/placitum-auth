package decide

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/exemt/placitum-auth/internal/audit"
	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/jwt"
	"github.com/exemt/placitum-auth/internal/learn"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/token"
)

const (
	CodeOK               = "AUTH_OK"
	CodeOff              = "AUTH_OFF"
	CodeSelf             = "AUTH_SELF"
	CodeObserve          = "AUTH_OBSERVE"
	CodeRenew            = "AUTH_RENEW"
	CodeReauth           = "AUTH_REAUTH"
	CodeSkipped          = "AUTH_SKIPPED"
	CodeNoSession        = "AUTH_NO_SESSION"
	CodeSessionBad       = "AUTH_SESSION_BAD"
	CodeSessionExpired   = "AUTH_SESSION_EXPIRED"
	CodeSessionBind      = "AUTH_SESSION_BIND"
	CodeSessionScope     = "AUTH_SESSION_SCOPE"
	CodeSessionSource    = "AUTH_SESSION_SOURCE"
	CodeSessionRevoked   = "AUTH_SESSION_REVOKED"
	CodeListUnavailable  = "AUTH_LIST_UNAVAILABLE"
	CodeStoreUnavailable = "AUTH_STORE_UNAVAILABLE"
	CodeGeoUnavailable   = "AUTH_GEO_UNAVAILABLE"
	CodeForbidden        = "AUTH_FORBIDDEN"
	CodeUnknownProfile   = "AUTH_UNKNOWN_PROFILE"
	CodeWrongPhase       = "AUTH_PHASE_NOT_SUPPORTED"
)

const (
	FindingNoSession      = "auth-no-session"
	FindingSessionBad     = "auth-session-bad"
	FindingSessionRevoked = "auth-session-revoked"
	FindingForbidden      = "auth-forbidden"
	FindingUnknownProfile = "auth-unknown-profile"
	FindingStore          = "auth-store-unavailable"
	FindingListDown       = "auth-list-unavailable"
)

type Sessions interface {
	Contains(subject, sid string) (ok, ready bool)
	Lookup(subject, sid string) (entry livelist.Entry, ok, ready bool)
}

type Input struct {
	Profile *config.Profile
	Ask     string

	Method   string
	URI      string
	Args     string
	ClientIP string

	Headers   []protocol.Header
	Cookie    string
	UserAgent string
	Accept    string

	SecFetchDest string

	UpgradeInsecure bool

	Prior []protocol.PriorVerdict

	StoreUnavailable string

	Now time.Time
}

type Result struct {
	Verdict string
	Code    string
	Text    string

	Response       string
	RedirectURL    string
	RedirectStatus int

	Inline bool

	Cookies []protocol.Cookie
	Headers map[string]string

	Session  *token.Session
	Findings []audit.Finding
	Engine   map[string]any

	Sessions []protocol.Session

	Event string
}

func Check(in Input, key *token.Key, sessions Sessions) (res Result) {
	if in.Profile == nil {
		return Result{
			Verdict: protocol.VerdictError,
			Code:    CodeUnknownProfile,
			Text:    in.Ask,
			Findings: []audit.Finding{{
				Code:     FindingUnknownProfile,
				Severity: audit.SeverityCritical,
				Target:   audit.TargetConn,
				Rule:     in.Ask,
			}},
		}
	}

	p := in.Profile

	engine := map[string]any{"profile": p.Name, "mode": p.Mode}

	if p.Mode == config.ModeObserve {
		engine["passive"] = true
	}

	if in.StoreUnavailable != "" {
		engine["store"] = in.StoreUnavailable
	}

	if p.Mode == config.ModeOff {
		return allow(p, nil, CodeOff, engine)
	}

	if p.OwnPath(in.URI) {
		engine["self"] = true

		return allow(p, nil, CodeSelf, engine)
	}

	asked := priorAsk(in.Prior, p)

	if len(asked.outcomes) != 0 {
		engine["actions"] = asked.outcomes
	}

	sess, code, finding := open(in, p, key, sessions)

	defer func() {
		res.Event = eventOf(sess, code, res)
	}()

	if code == CodeListUnavailable {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     code,
			Findings: finding,
			Engine:   engine,
		}
	}

	if sess != nil && !p.Allows(sess.Groups) {
		engine["forbidden"] = strings.Join(p.Gate.Groups, ",")

		if p.Mode == config.ModeObserve {
			engine["would_verdict"] = protocol.VerdictDeny
			engine["would_code"] = CodeForbidden

			res := allow(p, sess, CodeObserve, engine)
			res.Findings = forbidden(sess, p)

			return res
		}

		return Result{
			Verdict:  protocol.VerdictDeny,
			Code:     CodeForbidden,
			Response: p.Gate.ForbiddenResponse,
			Findings: forbidden(sess, p),
			Engine:   engine,
		}
	}

	if sess != nil {
		if asked.reauth && !asked.skip && reauthDue(in, p, sess) {
			engine["reauth"] = true

			if p.Mode == config.ModeObserve {
				engine["would_verdict"] = wouldBe(in, p)
				engine["would_code"] = CodeReauth

				res := allow(p, sess, CodeObserve, engine)
				res.Findings = finding

				return res
			}

			if navigational(in, p) {
				res := gate(in, p, key, CodeReauth, engine)
				res.Findings = finding

				return res
			}

			return Result{
				Verdict:  protocol.VerdictDeny,
				Code:     CodeReauth,
				Response: p.Gate.DenyResponse,
				Findings: finding,
				Engine:   engine,
			}
		}

		if sess.NeedsRenew(in.Now) && navigational(in, p) {
			if p.Mode == config.ModeObserve {
				engine["renew"] = true
				engine["would_verdict"] = protocol.VerdictRedirect
				engine["would_code"] = CodeRenew

				return allow(p, sess, CodeObserve, engine)
			}

			return renew(in, p, engine)
		}

		return allow(p, sess, CodeOK, engine)
	}

	if asked.skip {
		res := allow(p, nil, CodeSkipped, engine)
		res.Findings = finding

		return res
	}

	if p.Mode == config.ModeObserve {
		engine["would_verdict"] = wouldBe(in, p)
		engine["would_code"] = code

		res := allow(p, nil, CodeObserve, engine)
		res.Findings = finding

		return res
	}

	if navigational(in, p) {
		res := gate(in, p, key, code, engine)
		res.Findings = finding

		return res
	}

	return Result{
		Verdict:  protocol.VerdictDeny,
		Code:     code,
		Response: p.Gate.DenyResponse,
		Findings: finding,
		Engine:   engine,
	}
}

func gate(in Input, p *config.Profile, key *token.Key, code string,
	engine map[string]any) Result {

	res := redirect(in, p, key, code, engine)

	if p.FormInline() && res.Verdict == protocol.VerdictRedirect {
		res.Verdict = protocol.VerdictDeny
		res.Response = p.Gate.DenyResponse
		res.Inline = true
		engine["inline"] = true
	}

	return res
}

func open(in Input, p *config.Profile, key *token.Key, sessions Sessions) (
	*token.Session, string, []audit.Finding) {

	switch p.Src.Provider {
	case config.ProviderJWT:
		return openJWT(in, p.Src)

	case config.ProviderApp:
		return openApp(in, p.Src, sessions)
	}

	if in.Cookie == "" {
		return nil, CodeNoSession, absent(in)
	}

	src := p.Src

	want := token.Bind{}

	if src.BindsNet() {
		want.Net = token.Subnet(in.ClientIP, src.Session.Subnet.V4, src.Session.Subnet.V6)
	}

	if src.BindsUA() {
		want.UA = token.Fingerprint(in.UserAgent)
	}

	sess, err := key.OpenSession(in.Cookie, in.Now, want)

	switch {
	case errors.Is(err, token.ErrExpired):
		return nil, CodeSessionExpired, nil

	case errors.Is(err, token.ErrBind):
		return nil, CodeSessionBind, bad(FindingSessionBad, "bind")

	case err != nil:
		return nil, CodeSessionBad, bad(FindingSessionBad, "signature")
	}

	if sess.Scope != "" && sess.Scope != src.Session.Cookie {
		return nil, CodeSessionScope, nil
	}

	if sess.Iss != src.Name {
		return nil, CodeSessionSource, nil
	}

	if src.List.Enabled() && in.Now.Sub(time.Unix(sess.Issued, 0)) > src.List.Grace.D() {
		if sessions == nil {
			return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
		}

		listed, ready := sessions.Contains(src.List.Sessions, sess.SID)

		if !ready {
			return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
		}

		if !listed {
			return nil, CodeSessionRevoked, bad(FindingSessionRevoked, sess.SID)
		}
	}

	return sess, CodeOK, nil
}

func absent(in Input) []audit.Finding {
	if in.StoreUnavailable == "" {
		return nil
	}

	return []audit.Finding{{
		Code:     FindingStore,
		Severity: audit.SeverityHigh,
		Target:   audit.TargetConn,
		Rule:     in.StoreUnavailable,
	}}
}

func openJWT(in Input, src *config.Source) (*token.Session, string, []audit.Finding) {
	j := src.Providers.JWT

	raw := in.Cookie

	if j.Header != "" {
		raw = bearer(headerValue(in.Headers, j.Header), j.Prefix)
	}

	if raw == "" {
		return nil, CodeNoSession, absent(in)
	}

	tok, err := jwt.Parse(raw)
	if err != nil {
		return nil, CodeSessionBad, bad(FindingSessionBad, "malformed")
	}

	if j.Verify.Alg != config.JWTAlgNone {
		if err := tok.Verify(j.Verify.Alg, j.Key); err != nil {
			return nil, CodeSessionBad, bad(FindingSessionBad, "signature")
		}
	}

	leeway := int64(j.Verify.Leeway.D().Seconds())
	now := in.Now.Unix()

	expiry, hasExpiry := tok.Int(j.Claims.Expiry)
	if hasExpiry && now > expiry+leeway {
		return nil, CodeSessionExpired, nil
	}

	if nbf, ok := tok.Int("nbf"); ok && now < nbf-leeway {
		return nil, CodeSessionBad, bad(FindingSessionBad, "nbf")
	}

	if j.Verify.Issuer != "" && tok.String("iss") != j.Verify.Issuer {
		return nil, CodeSessionSource, bad(FindingSessionBad, "issuer")
	}

	if j.Verify.Audience != "" && !contains(tok.Strings("aud"), j.Verify.Audience) {
		return nil, CodeSessionScope, bad(FindingSessionBad, "audience")
	}

	id := tok.String(j.Claims.Session)

	if id == "" {
		id = tok.String("jti")
	}

	if id == "" {
		id = tok.Hash()
	}

	issued, _ := tok.Int(j.Claims.Issued)

	return &token.Session{
		SID:    id,
		Sub:    tok.String(j.Claims.User),
		Issued: issued,
		Expiry: expiry,
		Iss:    src.Name,
		AMR:    []string{"jwt"},
		Groups: tok.Strings(j.Claims.Groups),
	}, CodeOK, nil
}

func openApp(in Input, src *config.Source, sessions Sessions) (
	*token.Session, string, []audit.Finding) {

	if in.Cookie == "" {
		return nil, CodeNoSession, absent(in)
	}

	id := learn.Hash(in.Cookie)

	if sessions == nil {
		return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
	}

	entry, listed, ready := sessions.Lookup(src.List.Sessions, id)

	if !ready {
		return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
	}

	if !listed {
		return nil, CodeNoSession, nil
	}

	return &token.Session{
		SID:    id,
		Sub:    learn.UserOf(entry.Reason),
		Expiry: entry.Expires / 1000,
		Iss:    src.Name,
		AMR:    []string{"app"},
	}, CodeOK, nil
}

func headerValue(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if strings.EqualFold(h.Name(), name) {
			return h.Value()
		}
	}

	return ""
}

func bearer(value, prefix string) string {
	value = strings.TrimSpace(value)

	if prefix == "" {
		return value
	}

	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}

	return strings.TrimSpace(value[len(prefix):])
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}

	return false
}

type ask struct {
	reauth bool
	skip   bool

	outcomes []ActionOutcome
}

const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Value int    `json:"value,omitempty"`
	Delta int    `json:"delta,omitempty"`

	Outcome string `json:"outcome"`
}

func priorAsk(prior []protocol.PriorVerdict, p *config.Profile) ask {
	var a ask

	for _, v := range prior {
		if v.Phase != "" && v.Phase != protocol.PhaseRequest {
			continue
		}

		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, p)
		}
	}

	return a
}

func (a *ask) deliver(from string, act protocol.Action, p *config.Profile) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Value:   act.Value,
		Delta:   act.Delta,
		Outcome: OutcomeNoRule,
	}

	for _, r := range p.Trigger.Prior {
		if r.From != config.AnyInspector && r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		switch act.Do {
		case protocol.DoReauth:
			a.reauth = true

		case protocol.DoSkip:
			a.skip = true
		}

		out.Outcome = OutcomeApplied
	}

	a.outcomes = append(a.outcomes, out)
}

func eventOf(sess *token.Session, code string, res Result) string {
	if _, forbidden := res.Engine["forbidden"]; forbidden {
		return config.OnForbidden
	}

	if sess != nil {
		return config.OnAuthenticated
	}

	switch code {
	case CodeNoSession:
		return config.OnAnonymous

	case CodeListUnavailable, "":
		return ""
	}

	return config.OnInvalid
}

func reauthDue(in Input, p *config.Profile, sess *token.Session) bool {
	after := p.Trigger.ReauthAfter.D()
	if after == 0 {
		return true
	}

	return in.Now.Unix() >= sess.Issued+int64(after.Seconds())
}

func forbidden(sess *token.Session, p *config.Profile) []audit.Finding {
	return []audit.Finding{{
		Code:     FindingForbidden,
		Severity: audit.SeverityHigh,
		Target:   audit.TargetConn,
		Rule:     sess.Sub + " not in " + strings.Join(p.Gate.Groups, ","),
	}}
}

func bad(code, rule string) []audit.Finding {
	return []audit.Finding{{
		Code:     code,
		Severity: audit.SeverityMedium,
		Target:   audit.TargetConn,
		Rule:     rule,
	}}
}

func allow(p *config.Profile, s *token.Session, code string, engine map[string]any) Result {
	res := Result{
		Verdict: protocol.VerdictAllow,
		Code:    code,
		Headers: map[string]string{},
		Session: s,
		Engine:  engine,
	}

	user, groups, method := "", "", ""

	if s != nil {
		user = s.Sub
		groups = strings.Join(s.Groups, ",")
		method = strings.Join(s.AMR, "+")

		engine["sub"] = s.Sub
		engine["sid"] = s.SID
	}

	if p.Src != nil {
		setHeader(res.Headers, p.Src.Upstream.User, user)
		setHeader(res.Headers, p.Src.Upstream.Groups, groups)
		setHeader(res.Headers, p.Src.Upstream.Method, method)
	}

	res.Sessions = sessionsOf(p.Src, s)

	return res
}

func sessionsOf(src *config.Source, s *token.Session) []protocol.Session {
	if src == nil || s == nil {
		return nil
	}

	entry := protocol.Session{
		Source:   src.Name,
		Kind:     protocol.SessionOwn,
		User:     s.Sub,
		ID:       s.SID,
		Verified: true,
		Issued:   s.Issued,
		Expires:  s.Expiry,
		Groups:   s.Groups,
	}

	switch src.Provider {
	case config.ProviderJWT:
		entry.Kind = protocol.SessionJWT
		entry.Verified = src.Providers.JWT != nil &&
			src.Providers.JWT.Verify.Alg != config.JWTAlgNone

	case config.ProviderApp:
		entry.Kind = protocol.SessionApp
	}

	return []protocol.Session{entry}
}

func setHeader(dst map[string]string, name, value string) {
	if name == "" {
		return
	}

	dst[name] = value
}

func redirect(in Input, p *config.Profile, key *token.Key, code string,
	engine map[string]any) Result {

	if p.Src.External() {
		if p.Src.Login.URI == "" {
			return Result{
				Verdict:  protocol.VerdictDeny,
				Code:     code,
				Response: p.Gate.DenyResponse,
				Engine:   engine,
			}
		}

		return Result{
			Verdict:        protocol.VerdictRedirect,
			Code:           code,
			RedirectURL:    p.Src.Login.URI,
			RedirectStatus: p.Gate.RedirectStatus,
			Engine:         engine,
		}
	}

	back := returnPath(in.URI, in.Args)

	ticket := &token.Ticket{
		Nonce:  token.NewID(),
		Return: back,
		Scope:  p.Src.Name,
		Expiry: in.Now.Add(p.Src.Ticket.TTL.D()).Unix(),
	}

	sealed, err := key.SealTicket(ticket)
	if err != nil {
		return Result{
			Verdict:  protocol.VerdictDeny,
			Code:     code,
			Response: p.Gate.DenyResponse,
			Engine:   engine,
		}
	}

	target := p.Src.Login.URI
	if back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	return Result{
		Verdict:        protocol.VerdictRedirect,
		Code:           code,
		RedirectURL:    target,
		RedirectStatus: p.Gate.RedirectStatus,
		Cookies: []protocol.Cookie{{
			Name:   p.Src.Ticket.Cookie,
			Value:  sealed,
			Path:   p.Src.Login.URI,
			MaxAge: int(p.Src.Ticket.TTL.D().Seconds()),
		}},
		Engine: engine,
	}
}

func renew(in Input, p *config.Profile, engine map[string]any) Result {
	back := returnPath(in.URI, in.Args)

	target := strings.TrimRight(p.Src.Login.URI, "/") + "/renew"
	if back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	engine["renew"] = true

	return Result{
		Verdict:        protocol.VerdictRedirect,
		Code:           CodeRenew,
		RedirectURL:    target,
		RedirectStatus: p.Gate.RedirectStatus,
		Engine:         engine,
	}
}

func navigational(in Input, p *config.Profile) bool {
	if !p.RedirectsMethod(in.Method) {
		return false
	}

	if p.Gate.HTMLOnly && !showsPage(in) {
		return false
	}

	return true
}

func showsPage(in Input) bool {
	switch in.SecFetchDest {
	case "":
		return in.UpgradeInsecure || acceptsHTML(in.Accept)
	case "document", "iframe", "frame":
		return true
	default:
		return false
	}
}

func acceptsHTML(accept string) bool {
	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml")
}

func wouldBe(in Input, p *config.Profile) string {
	if navigational(in, p) {
		return protocol.VerdictRedirect
	}

	return protocol.VerdictDeny
}

func returnPath(uri, args string) string {
	const max = 1024

	if uri == "" || uri[0] != '/' {
		return ""
	}

	if strings.HasPrefix(uri, "//") {
		return ""
	}

	out := uri
	if args != "" {
		out += "?" + args
	}

	if len(out) > max {
		return ""
	}

	for i := 0; i < len(out); i++ {
		c := out[i]
		if c < 0x21 || c > 0x7e || c == '\\' {
			return ""
		}
	}

	return out
}
