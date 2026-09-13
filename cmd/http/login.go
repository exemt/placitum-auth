/*
 * Проверка формы: билет, лимит попыток, цепочка факторов, выдача сессии.
 *
 * Порядок здесь не косметика. Билет проверяется до провайдеров, потому что
 * дешёвая проверка обязана отсекать раньше дорогой; блокировка -- до
 * провайдеров, потому что иначе подбор упирался бы в bcrypt, а не в счётчик;
 * nonce гасится до провайдеров, потому что иначе один билет давал бы
 * неограниченное число попыток.
 */

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
	msgBadCredentials = "Неверные данные."
	msgStaleForm      = "Форма устарела. Попробуйте ещё раз."
	msgUnavailable    = "Служба проверки недоступна. Попробуйте позже."
	msgNotAllowed     = "Доступ запрещён."
	msgFirstGate      = "Сначала пройдите первую проверку входа."

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

	/*
	 * Двойная отправка: nonce едет и в cookie, и в поле формы. Совпадение
	 * доказывает, что форму отправили с нашей страницы, а не со стороннего
	 * сайта -- SameSite=Lax закрывает не все способы.
	 */
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
		s.form(w, r, src, fmt.Sprintf("Слишком много попыток. Повторите через %s.",
			humanLeft(left)))

		return
	}

	// Билет одноразовый: гасим до провайдеров, иначе один nonce давал бы
	// сколько угодно попыток подбора. Дальше любая неудача показывает форму с
	// новым билетом (reform): прежний уже погашен.
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

	/*
	 * Стыкованный источник: личность приносит сессия первого. Её нет или она
	 * не к этому клиенту -- первая калитка не пройдена, и форма это говорит,
	 * а не пытается проверить код неизвестно чей.
	 */
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

/*
 * accepted выписывает сессию. Привязка снимается здесь и только здесь: адрес и
 * User-Agent того запроса, в котором вошли, -- это и есть то, к чему токен
 * привязан.
 */
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
		// Scope -- имя cookie источника; Iss -- сам источник. Профили одного
		// источника принимают этот токен, профили чужих -- нет, что бы ни было
		// написано в их куках.
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

/*
 * rejected считает неудачу и показывает форму заново.
 *
 * Недоступность каталога в счётчик не идёт: это авария контура, и запирать за
 * неё пользователя значило бы превращать сбой LDAP в блокировку учётных
 * записей.
 */
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

/*
 * burnCode гасит принятый код TOTP. Без этого перехваченный код работает ещё
 * полшага окна -- ровно то, от чего одноразовый пароль и защищает.
 *
 * Гасится он после успеха всей цепочки: гасить до проверки пароля значило бы
 * дать любому желающему сжигать чужие коды одной формой.
 */
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

/*
 * priorIdentity открывает сессию первой калитки (identity.from): тот же
 * процесс, тот же ключ, cookie с именем из её источника. Проверяется и
 * привязка: чужая сессия с другой подсети личностью не считается.
 */
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

/*
 * lockScopes -- две оси счёта. По адресу, чтобы один клиент не перебирал много
 * логинов; по логину, чтобы много клиентов не перебирали один. Ключи несут имя
 * источника: источники независимы, и блокировка логина в одном не должна
 * запирать того же человека в другом.
 */
func lockScopes(src *config.Source, c provider.Credentials) []string {
	scopes := []string{src.Name + "/ip:" + c.ClientIP}

	if login := strings.ToLower(strings.TrimSpace(c.Login)); login != "" {
		scopes = append(scopes, src.Name+"/user:"+login)
	}

	return scopes
}

// humanLeft округляет вверх: "0 мин" на живой блокировке -- приглашение
// попробовать ещё раз, а лишняя минута сверху -- перебор в другую сторону.
func humanLeft(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d с", int(math.Ceil(d.Seconds())))
	}

	return fmt.Sprintf("%d мин", int(math.Ceil(d.Minutes())))
}
