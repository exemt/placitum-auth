/*
 * Список логинов и паролей контура. Файл едет с профилем и перечитывается
 * вместе с ним.
 *
 * В файле только bcrypt-хеши: открытый пароль отвергается при загрузке
 * профиля, а не при первой попытке входа. Файл лежит в git оператора и в
 * образе, и это единственная причина, по которой формат такой строгий.
 */

package provider

import (
	"context"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/exemt/placitum-auth/internal/config"
)

/*
 * Хеш заведомо несуществующего пароля. Нужен, чтобы неизвестный логин стоил
 * столько же времени, сколько известный: без этого перечисление учётных
 * записей делается секундомером, и никакая одинаковость текста ошибки не
 * помогает.
 */
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

	// Сравнение выполняется всегда, включая неизвестный логин.
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
	id.Groups = append(id.Groups, user.Groups...)

	if user.Display != "" {
		id.Display = user.Display
	}

	id.with("pwd")

	return id, nil
}
