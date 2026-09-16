package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/provider"
	"github.com/exemt/placitum-auth/internal/token"
)

const (
	msgBadCredentials = "Invalid credentials."
	msgStaleForm      = "The form has expired. Please try again."
	msgUnavailable    = "The sign-in service is unavailable. Please try again later."
	msgNotAllowed     = "Access denied."
	msgFirstGate      = "Complete the first sign-in step first."

	formLimit = 16 << 10
)

func (s *server) submit(w http.ResponseWriter, r *http.Request, src *config.Source) {
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)

	if err := r.ParseForm(); err != nil {
		s.form(w, r, src, msgStaleForm)

		return
	}

	now := time.Now()

	ticket, err := s.cfg.Key.OpenTicket(cookieValue(r, src.Ticket.Cookie), now)
	if err != nil || ticket.Scope != src.Name {
		s.form(w, r, src, msgStaleForm)

		return
	}

	if subtle.ConstantTimeCompare([]byte(ticket.Nonce),
		[]byte(r.PostFormValue("csrf"))) != 1 {
		s.form(w, r, src, msgStaleForm)

		return
	}

	creds := provider.Credentials{
		Login:    strings.TrimSpace(r.PostFormValue("login")),
		Password: r.PostFormValue("password"),
		Code:     strings.TrimSpace(r.PostFormValue("code")),
		ClientIP: s.clientIP(r),
	}

	scopes := lockScopes(src, creds)

	if left := s.lockedFor(r.Context(), scopes); left > 0 {
		s.log.Warn("locked out",
			"source", src.Name, "login", creds.Login, "client_ip", creds.ClientIP,
			"left", left.String())
		s.form(w, r, src, fmt.Sprintf("Too many attempts. Try again in %s.",
			humanLeft(left)))

		return
	}

	fresh, err := s.roster.Burn(r.Context(), "nonce", ticket.Nonce, src.Ticket.TTL.D())
	if err != nil {
		s.log.Error("nonce burn failed", "error", err.Error())
		s.reform(w, r, src, msgUnavailable)

		return
	}

	if !fresh {
		s.reform(w, r, src, msgStaleForm)

		return
	}

	prov, err := provider.Build(src, s.secrets)
	if err != nil {
		s.fail(w, "cannot build the provider", err)

		return
	}

	prior, err := s.priorIdentity(r, src)
	if err != nil {
		s.reform(w, r, src, msgFirstGate)

		return
	}

	id, err := provider.Run(r.Context(), prov, creds, prior)
	if err != nil {
		s.rejected(w, r, src, creds, scopes, err)

		return
	}

	if ok, why := s.burnCode(r.Context(), src, id, creds); !ok {
		s.rejected(w, r, src, creds, scopes, why)

		return
	}

	s.accepted(w, r, src, ticket, id, creds)
}

func (s *server) accepted(w http.ResponseWriter, r *http.Request, src *config.Source,
	ticket *token.Ticket, id *provider.Identity, creds provider.Credentials) {

	now := time.Now()
	bind := s.bindOf(r, src)

	sess := &token.Session{
		SID:    token.NewID(),
		Sub:    id.Subject,
		Issued: now.Unix(),
		Expiry: now.Add(src.Session.TTL.D()).Unix(),
		Renew:  renewAt(now, src),
		Scope:  src.Session.Cookie,
		Iss:    src.Name,
		Net:    bind.Net,
		UA:     bind.UA,
		AMR:    id.AMR,
		Groups: id.Groups,
	}

	for _, scope := range lockScopes(src, creds) {
		if err := s.roster.Clear(r.Context(), scope); err != nil {
			s.log.Warn("counter reset failed", "error", err.Error())
		}
	}

	if err := s.issue(w, r, src, sess); err != nil {
		s.fail(w, "cannot issue the session", err)

		return
	}

	s.log.Info("login",
		"source", src.Name,
		"sub", sess.Sub,
		"sid", sess.SID,
		"amr", strings.Join(sess.AMR, "+"),
		"client_ip", creds.ClientIP,
	)

	back := ticket.Return
	if back == "" {
		back = s.backTo(r)
	}

	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *server) rejected(w http.ResponseWriter, r *http.Request, src *config.Source,
	creds provider.Credentials, scopes []string, cause error) {

	msg := msgBadCredentials

	switch {
	case errors.Is(cause, provider.ErrUnavailable):
		msg = msgUnavailable

		s.log.Error("provider unavailable",
			"source", src.Name, "login", creds.Login, "error", cause.Error())

		s.reform(w, r, src, msg)

		return

	case errors.Is(cause, provider.ErrNotAllowed):
		msg = msgNotAllowed
	}

	s.log.Warn("login rejected",
		"source", src.Name,
		"login", creds.Login,
		"client_ip", creds.ClientIP,
		"reason", cause.Error(),
	)

	s.count(r.Context(), src, scopes)
	s.reform(w, r, src, msg)
}

func (s *server) count(ctx context.Context, src *config.Source, scopes []string) {
	if src.Lockout.Attempts <= 0 {
		return
	}

	for _, scope := range scopes {
		n, err := s.roster.Fail(ctx, scope, src.Lockout.Window.D())
		if err != nil {
			s.log.Warn("attempt counter failed", "scope", scope, "error", err.Error())

			continue
		}

		if n < src.Lockout.Attempts {
			continue
		}

		if err := s.roster.Lock(ctx, scope, src.Lockout.Lock.D()); err != nil {
			s.log.Warn("lock failed", "scope", scope, "error", err.Error())

			continue
		}

		s.log.Warn("locked", "scope", scope, "attempts", n, "for", src.Lockout.Lock.D().String())
	}
}

func (s *server) lockedFor(ctx context.Context, scopes []string) time.Duration {
	var worst time.Duration

	for _, scope := range scopes {
		left, err := s.roster.LockedFor(ctx, scope)
		if err != nil {
			s.log.Warn("lock check failed", "scope", scope, "error", err.Error())

			continue
		}

		if left > worst {
			worst = left
		}
	}

	return worst
}

func (s *server) burnCode(ctx context.Context, src *config.Source, id *provider.Identity,
	creds provider.Credentials) (bool, error) {

	c := src.Providers.Code
	if src.Provider != config.ProviderCode || c == nil || c.Kind != config.CodeTOTP ||
		creds.Code == "" {
		return true, nil
	}

	window := c.Period.D() * time.Duration(2*c.Skew+2)

	fresh, err := s.roster.Burn(ctx, "totp", id.Subject+":"+creds.Code, window)
	if err != nil {
		return false, fmt.Errorf("%w: %s", provider.ErrUnavailable, err)
	}

	if !fresh {
		return false, fmt.Errorf("code replay: %w", provider.ErrInvalid)
	}

	return true, nil
}

func (s *server) priorIdentity(r *http.Request, src *config.Source) (*provider.Identity, error) {
	if src.Identity.From == "" {
		return nil, nil
	}

	from, ok := s.profiles.Current().Source(src.Identity.From)
	if !ok {
		return nil, fmt.Errorf("identity.from: unknown source %q", src.Identity.From)
	}

	raw := cookieValue(r, from.Session.Cookie)
	if raw == "" {
		return nil, provider.ErrNotAllowed
	}

	sess, err := s.cfg.Key.OpenSession(raw, time.Now(), s.bindOf(r, from))
	if err != nil || sess.Scope != from.Session.Cookie || sess.Iss != from.Name ||
		!s.alive(from, sess) {
		return nil, provider.ErrNotAllowed
	}

	return &provider.Identity{
		Subject: sess.Sub,
		Groups:  append([]string(nil), sess.Groups...),
		AMR:     append([]string(nil), sess.AMR...),
	}, nil
}

func lockScopes(src *config.Source, c provider.Credentials) []string {
	scopes := []string{src.Name + "/ip:" + c.ClientIP}

	if login := strings.ToLower(strings.TrimSpace(c.Login)); login != "" {
		scopes = append(scopes, src.Name+"/user:"+login)
	}

	return scopes
}

func humanLeft(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(math.Ceil(d.Seconds())))
	}

	return fmt.Sprintf("%d min", int(math.Ceil(d.Minutes())))
}
