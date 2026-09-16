package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/exemt/placitum-auth/internal/config"
)

var (
	ErrInvalid     = errors.New("invalid credentials")
	ErrNotAllowed  = errors.New("not allowed")
	ErrUnavailable = errors.New("provider is unavailable")
)

const (
	FieldLogin    = "login"
	FieldPassword = "password"
	FieldCode     = "code"
)

type Credentials struct {
	Login    string
	Password string
	Code     string
	ClientIP string
}

type Identity struct {
	Subject string
	Display string
	Groups  []string
	AMR     []string
}

func (id *Identity) with(amr string) {
	for _, a := range id.AMR {
		if a == amr {
			return
		}
	}

	id.AMR = append(id.AMR, amr)
}

type Secrets interface {
	Get(ctx context.Context, id string) (string, error)
}

type Provider interface {
	Name() string
	Fields() []string
	Verify(ctx context.Context, c Credentials, id *Identity) (*Identity, error)
}

func Build(src *config.Source, sec Secrets) (Provider, error) {
	switch src.Provider {
	case config.ProviderLocal:
		return &Local{Users: src.Users, Secrets: sec}, nil

	case config.ProviderCode:
		return &Code{Cfg: src.Providers.Code, Users: src.Users, Secrets: sec}, nil

	case config.ProviderLDAP:
		return &LDAP{Cfg: src.Providers.LDAP, Secrets: sec}, nil

	case config.ProviderNTLM:
		return &NTLM{Cfg: src.Providers.NTLM, Secrets: sec}, nil
	}

	return nil, fmt.Errorf("unknown provider %q", src.Provider)
}

func Run(ctx context.Context, p Provider, c Credentials, prior *Identity) (*Identity, error) {
	id, err := p.Verify(ctx, c, prior)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.Name(), err)
	}

	if id == nil || id.Subject == "" {
		return nil, fmt.Errorf("%s: %w", p.Name(), ErrInvalid)
	}

	return id, nil
}

func allowed(groups, want []string) bool {
	return config.GroupsAllow(groups, want)
}
