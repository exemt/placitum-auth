package provider

import (
	"context"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/token"
)

const decoyHash = "$2a$12$C6UzMDM.H6dfI/f/IKcEe.7BQmv1oPUC4NUnfr5xNgUEy6Z1sKNIu"

type Local struct {
	Users   map[string]*config.User
	Secrets Secrets
}

func (*Local) Name() string { return config.ProviderLocal }

func (*Local) Fields() []string { return []string{FieldLogin, FieldPassword} }

func (l *Local) Verify(_ context.Context, c Credentials, id *Identity) (*Identity, error) {
	login := strings.ToLower(strings.TrimSpace(c.Login))

	user := l.Users[login]

	hash := decoyHash
	if user != nil && user.Password != "" {
		hash = user.Password
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(c.Password))

	if user == nil || err != nil || c.Password == "" {
		return nil, ErrInvalid
	}

	if !user.Active() {
		return nil, ErrNotAllowed
	}

	if id == nil {
		id = &Identity{}
	}

	id.Subject = user.Login
	id.Cred = token.Credential(user.Password)
	id.Groups = append(id.Groups, user.Groups...)

	if user.Display != "" {
		id.Display = user.Display
	}

	id.with("pwd")

	return id, nil
}
