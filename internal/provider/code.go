package provider

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/otp"
)

type Code struct {
	Cfg     *config.CodeProvider
	Users   map[string]*config.User
	Secrets Secrets
	Now     func() time.Time
}

func (*Code) Name() string { return config.ProviderCode }

func (*Code) Fields() []string { return []string{FieldCode} }

func (c *Code) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}

	return time.Now()
}

func (c *Code) Verify(ctx context.Context, cr Credentials, id *Identity) (*Identity, error) {
	if c.Cfg == nil {
		return nil, ErrUnavailable
	}

	entered := strings.TrimSpace(cr.Code)
	if entered == "" {
		return nil, ErrInvalid
	}

	switch c.Cfg.Kind {
	case config.CodeStatic:
		return c.static(entered, cr, id)

	default:
		return c.totp(ctx, entered, id)
	}
}

func (c *Code) secretOf(ctx context.Context, login string) (string, error) {
	user := c.Users[strings.ToLower(strings.TrimSpace(login))]
	if user == nil || !user.Active() {
		return "", ErrNotAllowed
	}

	if user.TOTPStore != "" {
		if c.Secrets == nil {
			return "", fmt.Errorf("%w: totp_store needs the contour key", ErrUnavailable)
		}

		secret, err := c.Secrets.Get(ctx, user.TOTPStore)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrUnavailable, err)
		}

		return secret, nil
	}

	return user.TOTP, nil
}

func (c *Code) totp(ctx context.Context, entered string, id *Identity) (*Identity, error) {
	if id == nil || id.Subject == "" {
		return nil, ErrNotAllowed
	}

	raw, err := c.secretOf(ctx, id.Subject)
	if err != nil {
		return nil, err
	}

	if raw == "" {
		return nil, ErrNotAllowed
	}

	secret, err := otp.Secret(raw)
	if err != nil {
		return nil, ErrNotAllowed
	}

	counter := otp.Counter(c.now(), c.Cfg.Period.D())

	for d := -c.Cfg.Skew; d <= c.Cfg.Skew; d++ {
		want := otp.At(secret, counter+int64(d), c.Cfg.Digits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(entered)) == 1 {
			id.with("totp")

			return id, nil
		}
	}

	return nil, ErrInvalid
}

func (c *Code) static(entered string, cr Credentials, id *Identity) (*Identity, error) {
	matched := false

	for _, hash := range c.Cfg.Codes {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(entered)) == nil {
			matched = true
		}
	}

	if !matched {
		return nil, ErrInvalid
	}

	if id == nil {
		id = &Identity{}
	}

	if id.Subject == "" {
		id.Subject = strings.TrimSpace(cr.Login)
		if id.Subject == "" {
			id.Subject = "code"
		}
	}

	id.with("code")

	return id, nil
}
