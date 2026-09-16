package main

import (
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/provider"
	"github.com/exemt/placitum-auth/internal/roster"
	"github.com/exemt/placitum-auth/internal/token"
	"github.com/exemt/placitum-shared/dataset"
)

const (
	actionForm   = ""
	actionRenew  = "renew"
	actionLogout = "logout"
	actionHealth = "healthz"
)

type server struct {
	cfg      *config.Config
	log      *slog.Logger
	profiles *config.Store
	roster   roster.Roster
	pages    *pages
	list     *dataset.Publisher
	sessions *livelist.Mirror
	secrets  provider.Secrets
}

func (s *server) alive(src *config.Source, sess *token.Session) bool {
	if !src.List.Enabled() {
		return true
	}

	if time.Since(time.Unix(sess.Issued, 0)) <= src.List.Grace.D() {
		return true
	}

	if s.sessions == nil {
		return false
	}

	listed, ready := s.sessions.Contains(src.List.Sessions, sess.SID)

	return ready && listed
}

type pages struct {
	login *template.Template
}

func loadPages(dir string) (*pages, error) {
	t, err := template.ParseFiles(path.Join(dir, "login.html"))
	if err != nil {
		return nil, err
	}

	return &pages{login: t}, nil
}

type view struct {
	Title       string
	Note        string
	Action      string
	Nonce       string
	Error       string
	AskLogin    bool
	AskPassword bool
	AskCode     bool
	Done        bool
	DoneText    string
	LoginURI    string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))

		return
	}

	src, action := route(s.profiles.Current(), r.URL.Path)
	if src == nil {
		http.NotFound(w, r)

		return
	}

	switch action {
	case actionHealth:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))

	case actionForm:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.form(w, r, src, "")

		case http.MethodPost:
			s.submit(w, r, src)

		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case actionRenew:
		s.renew(w, r, src)

	case actionLogout:
		s.logout(w, r, src)

	default:
		http.NotFound(w, r)
	}
}

func route(snap *config.Snapshot, uri string) (*config.Source, string) {
	var (
		best   *config.Source
		action string
	)

	for _, src := range snap.Sources() {
		base := src.Login.URI
		if base == "" || src.External() {
			continue
		}

		var rest string

		switch {
		case uri == base:
			rest = actionForm

		case strings.HasPrefix(uri, base+"/"):
			rest = strings.Trim(uri[len(base)+1:], "/")

		default:
			continue
		}

		if best == nil || len(src.Login.URI) > len(best.Login.URI) {
			best, action = src, rest
		}
	}

	return best, action
}

func (s *server) form(w http.ResponseWriter, r *http.Request, src *config.Source, msg string) {
	s.page(w, r, src, msg, false)
}

func (s *server) reform(w http.ResponseWriter, r *http.Request, src *config.Source, msg string) {
	s.page(w, r, src, msg, true)
}

func (s *server) page(w http.ResponseWriter, r *http.Request, src *config.Source, msg string,
	rotate bool) {

	ticket, _ := s.cfg.Key.OpenTicket(cookieValue(r, src.Ticket.Cookie), time.Now())
	if ticket != nil && ticket.Scope != src.Name {
		ticket = nil
	}

	back := localPath(r.URL.Query().Get("rd"))
	if back == "" && ticket != nil {
		back = ticket.Return
	}

	if rotate || ticket == nil || ticket.Return != back {
		fresh := &token.Ticket{
			Nonce:  token.NewID(),
			Return: back,
			Scope:  src.Name,
			Expiry: time.Now().Add(src.Ticket.TTL.D()).Unix(),
		}

		sealed, err := s.cfg.Key.SealTicket(fresh)
		if err != nil {
			s.fail(w, "cannot issue a login ticket", err)

			return
		}

		s.setCookie(w, src.Ticket.Cookie, sealed, src.Login.URI, src.Ticket.TTL.D())
		ticket = fresh
	}

	s.render(w, src, view{
		Nonce: ticket.Nonce,
		Error: msg,
	}, statusFor(msg))
}

func (s *server) renew(w http.ResponseWriter, r *http.Request, src *config.Source) {
	now := time.Now()

	sess, err := s.cfg.Key.OpenSession(cookieValue(r, src.Session.Cookie), now, s.bindOf(r, src))
	if err != nil || sess == nil || sess.Scope != src.Session.Cookie ||
		sess.Iss != src.Name || !s.alive(src, sess) {
		s.redirectToForm(w, r, src)

		return
	}

	sess.Issued = now.Unix()
	sess.Expiry = now.Add(src.Session.TTL.D()).Unix()
	sess.Renew = renewAt(now, src)

	if err := s.issue(w, r, src, sess); err != nil {
		s.fail(w, "cannot renew the session", err)

		return
	}

	s.log.Info("session renewed", "source", src.Name, "sub", sess.Sub, "sid", sess.SID)

	http.Redirect(w, r, s.backTo(r), http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, src *config.Source) {
	s.closeGate(w, r, src)

	if src.Identity.From != "" {
		if from, ok := s.profiles.Current().Source(src.Identity.From); ok {
			s.closeGate(w, r, from)
		}
	}

	s.render(w, src, view{
		Done:     true,
		DoneText: "You have been signed out.",
	}, http.StatusOK)
}

func (s *server) closeGate(w http.ResponseWriter, r *http.Request, src *config.Source) {
	now := time.Now()

	sess, err := s.cfg.Key.OpenSession(cookieValue(r, src.Session.Cookie), now, token.Bind{})
	if err == nil && sess != nil {
		s.forget(src, sess.SID, "AUTH_LOGOUT "+sess.Sub)

		s.log.Info("logout", "source", src.Name, "sub", sess.Sub, "sid", sess.SID)
	}

	s.clearCookie(w, src.Session.Cookie, "/")

	if src.List.Enabled() {
		s.clearCookie(w, src.List.Cookie, "/")
	}

	if src.Upstream.Cookie != "" {
		s.clearCookie(w, src.Upstream.Cookie, "/")
	}
}

func (s *server) issue(w http.ResponseWriter, r *http.Request, src *config.Source,
	sess *token.Session) error {

	sealed, err := s.cfg.Key.SealSession(sess)
	if err != nil {
		return err
	}

	ttl := time.Until(time.Unix(sess.Expiry, 0))

	s.setCookie(w, src.Session.Cookie, sealed, "/", ttl)
	s.clearCookie(w, src.Ticket.Cookie, src.Login.URI)

	if src.List.Enabled() {
		s.setCookie(w, src.List.Cookie, sess.SID, "/", ttl)
	}

	if err := s.identify(w, src, sess, ttl); err != nil {
		return err
	}

	s.remember(src, sess)

	return nil
}

func (s *server) identify(w http.ResponseWriter, src *config.Source,
	sess *token.Session, ttl time.Duration) error {

	if src.Upstream.Cookie == "" || s.cfg.AppKey == nil {
		return nil
	}

	if src.Upstream.TTL > 0 && src.Upstream.TTL.D() < ttl {
		ttl = src.Upstream.TTL.D()
	}

	sealed, err := s.cfg.AppKey.SealIdentity(&token.Identity{
		Sub:     sess.Sub,
		Display: sess.Sub,
		Groups:  sess.Groups,
		AMR:     sess.AMR,
		Issued:  sess.Issued,
		Expiry:  time.Now().Add(ttl).Unix(),
		SID:     sess.SID,
		Scope:   sess.Scope,
	})
	if err != nil {
		return err
	}

	s.setCookie(w, src.Upstream.Cookie, sealed, "/", ttl)

	return nil
}

func (s *server) remember(src *config.Source, sess *token.Session) {
	if !src.List.Enabled() || s.list == nil {
		return
	}

	ttl := time.Until(time.Unix(sess.Expiry, 0))
	if ttl > src.List.TTL.D() {
		ttl = src.List.TTL.D()
	}

	if err := s.list.Add(src.List.Sessions, sess.SID, ttl,
		"AUTH_LOGIN "+sess.Sub); err != nil {
		s.log.Warn("session list add failed", "sid", sess.SID, "error", err.Error())
	}
}

func (s *server) forget(src *config.Source, sid, reason string) {
	if !src.List.Enabled() || s.list == nil || sid == "" {
		return
	}

	if err := s.list.Remove(src.List.Sessions, sid, reason); err != nil {
		s.log.Warn("session list remove failed", "sid", sid, "error", err.Error())
	}
}

func (s *server) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) bindOf(r *http.Request, src *config.Source) token.Bind {
	var b token.Bind

	if src.BindsNet() {
		b.Net = token.Subnet(s.clientIP(r), src.Session.Subnet.V4, src.Session.Subnet.V6)
	}

	if src.BindsUA() {
		b.UA = token.Fingerprint(r.Header.Get("User-Agent"))
	}

	return b
}

func (s *server) clientIP(r *http.Request) string {
	return forwardedAddr(r.Header.Values(s.cfg.RealIPHeader), r.RemoteAddr)
}

func forwardedAddr(values []string, remoteAddr string) string {
	if n := len(values); n > 0 {
		last := values[n-1]

		if i := strings.LastIndexByte(last, ','); i >= 0 {
			last = last[i+1:]
		}

		if ip := strings.TrimSpace(last); net.ParseIP(ip) != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}

func (s *server) backTo(r *http.Request) string {
	if back := localPath(r.URL.Query().Get("rd")); back != "" {
		return back
	}

	return "/"
}

func (s *server) redirectToForm(w http.ResponseWriter, r *http.Request, src *config.Source) {
	target := src.Login.URI

	if back := localPath(r.URL.Query().Get("rd")); back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *server) render(w http.ResponseWriter, src *config.Source, v view, status int) {
	v.Title = src.Login.Title
	if v.Title == "" {
		v.Title = "Sign in"
	}

	v.Note = src.Login.Note
	v.Action = src.Login.URI
	v.LoginURI = src.Login.URI

	prov, err := provider.Build(src, s.secrets)
	if err != nil {
		s.fail(w, "cannot build the provider", err)

		return
	}

	for _, f := range prov.Fields() {
		switch f {
		case provider.FieldLogin:
			v.AskLogin = true
		case provider.FieldPassword:
			v.AskPassword = true
		case provider.FieldCode:
			v.AskCode = true
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)

	page := s.pages.login
	if src.LoginPage != nil {
		page = src.LoginPage
	}

	if err := page.Execute(w, v); err != nil {
		s.log.Error("render failed", "source", src.Name, "error", err.Error())
	}
}

func (s *server) fail(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "error", err.Error())
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func statusFor(msg string) int {
	if msg == "" {
		return http.StatusOK
	}

	return http.StatusUnauthorized
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}

	return c.Value
}

func renewAt(now time.Time, src *config.Source) int64 {
	if src.Session.RenewAfter <= 0 {
		return 0
	}

	return now.Add(src.Session.RenewAfter.D()).Unix()
}

func localPath(raw string) string {
	const max = 1024

	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || len(raw) > max {
		return ""
	}

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x21 || c > 0x7e || c == '\\' {
			return ""
		}
	}

	return raw
}
