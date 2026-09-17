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

	verifyWait = 5 * time.Second
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

	// The attempt is counted before the check, not after it: parallel submits would
	// otherwise all pass the lock test above and buy a guess each.
	counts, over := s.reserve(r.Context(), src, scopes)
	if over {
		s.log.Warn("locked out",
			"source", src.Name, "login", creds.Login, "client_ip", creds.ClientIP)
		s.reform(w, r, src, fmt.Sprintf("Too many attempts. Try again in %s.",
			humanLeft(src.Lockout.Lock.D())))

		return
	}

	release, ok := s.verifySlot(r.Context())
	if !ok {
		s.log.Warn("verification queue is full", "source", src.Name, "client_ip", creds.ClientIP)
		s.reform(w, r, src, msgUnavailable)

		return
	}

	id, err := provider.Run(r.Context(), prov, creds, prior)

	release()

	if err != nil {
		s.rejected(w, r, src, creds, scopes, counts, err)

		return
	}

	if ok, why := s.burnCode(r.Context(), src, id, creds); !ok {
		s.rejected(w, r, src, creds, scopes, counts, why)

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
		Expiry: expiryOf(now, src, now.Unix()),
		Renew:  renewAt(now, src),
		Born:   now.Unix(),
		Cred:   id.Cred,
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
	creds provider.Credentials, scopes []string, counts []int, cause error) {

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

	s.lockSpent(r.Context(), src, scopes, counts)
	s.reform(w, r, src, msg)
}

// reserve counts the attempt in every scope and says whether any of them is already
// past the limit. A successful login clears the counters.
func (s *server) reserve(ctx context.Context, src *config.Source, scopes []string) ([]int, bool) {
	counts := make([]int, len(scopes))

	if src.Lockout.Attempts <= 0 {
		return counts, false
	}

	over := false

	for i, scope := range scopes {
		n, err := s.roster.Fail(ctx, scope, src.Lockout.Window.D())
		if err != nil {
			s.log.Warn("attempt counter failed", "scope", scope, "error", err.Error())

			continue
		}

		counts[i] = n

		if n > src.Lockout.Attempts {
			over = true

			s.lock(ctx, src, scope, n)

			continue
		}

		// Lock drops the counter it has just spent. The lock is read after the count, so a
		// submit that starts that counter anew still meets the lock set beside it.
		if left, err := s.roster.LockedFor(ctx, scope); err == nil && left > 0 {
			over = true
		}
	}

	return counts, over
}

func (s *server) lockSpent(ctx context.Context, src *config.Source, scopes []string, counts []int) {
	if src.Lockout.Attempts <= 0 {
		return
	}

	for i, scope := range scopes {
		if i < len(counts) && counts[i] >= src.Lockout.Attempts {
			s.lock(ctx, src, scope, counts[i])
		}
	}
}

func (s *server) lock(ctx context.Context, src *config.Source, scope string, n int) {
	if err := s.roster.Lock(ctx, scope, src.Lockout.Lock.D()); err != nil {
		s.log.Warn("lock failed", "scope", scope, "error", err.Error())

		return
	}

	s.log.Warn("locked", "scope", scope, "attempts", n, "for", src.Lockout.Lock.D().String())
}

// verifySlot bounds password checks running at once: bcrypt is the expensive step an
// anonymous client can trigger, and without a bound a flood of submits takes every core.
func (s *server) verifySlot(ctx context.Context) (func(), bool) {
	if s.verify == nil {
		return func() {}, true
	}

	wait := time.NewTimer(verifyWait)
	defer wait.Stop()

	select {
	case s.verify <- struct{}{}:
		return func() { <-s.verify }, true

	case <-wait.C:
		return nil, false

	case <-ctx.Done():
		return nil, false
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
	// An IPv6 client owns its whole /64: counting single addresses there limits nothing.
	ip := c.ClientIP
	if subnet := token.Subnet(ip, 32, 64); subnet != "" && strings.Contains(ip, ":") {
		ip = subnet
	}

	scopes := []string{src.Name + "/ip:" + ip}

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
