/*
 * Провайдеры второго фактора. У источника входа ровно один: комбинации ("домен
 * плюс TOTP") собираются набором инспекторов на маршруте, а не списком внутри
 * источника. Второму источнику личность приносит сессия первого (identity.from).
 *
 * Провайдеры живут только в HTTP-процессе. Инспектор ни к файлу паролей, ни к
 * LDAP не ходит и ходить не должен: у него бюджет двадцать миллисекунд на весь
 * трафик маршрута, а bind к контроллеру домена уходит в сеть.
 */

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/exemt/placitum-auth/internal/config"
)

var (
	// ErrInvalid -- логин или пароль не сошлись. Наружу все три ошибки
	// выглядят одинаково: разница между "нет такого пользователя" и "пароль
	// не тот" -- это перечисление учётных записей.
	ErrInvalid = errors.New("invalid credentials")
	// ErrNotAllowed -- личность установлена, но допуска нет: выключенная
	// запись, чужая группа.
	ErrNotAllowed = errors.New("not allowed")
	// ErrUnavailable -- каталог не ответил. Отличается от ErrInvalid тем, что
	// это авария контура, а не неудача пользователя: в лог она идёт ошибкой, а
	// в счётчик попыток не идёт вовсе.
	ErrUnavailable = errors.New("provider is unavailable")
)

// Поля формы: форма показывает поля своего провайдера, и только их.
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

/*
 * Identity -- то, что известно о вошедшем. Для стыкованной калитки это вход:
 * личность из сессии первой, к которой TOTP добавляет свой фактор.
 */
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

/*
 * Secrets открывает store-объекты источника. Реализация -- internal/secrets;
 * nil означает, что источник пришёл из файла и ссылок store: в нём нет.
 */
type Secrets interface {
	Get(ctx context.Context, id string) (string, error)
}

type Provider interface {
	Name() string
	Fields() []string
	// Verify получает личность из первой калитки (identity.from) либо nil,
	// когда провайдер устанавливает её сам.
	Verify(ctx context.Context, c Credentials, id *Identity) (*Identity, error)
}

// Build собирает провайдер источника. Ошибка здесь -- ошибка конфигурации, и
// обнаружиться она обязана при загрузке источника, а не на первом входе.
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

/*
 * Run проводит проверку. prior -- личность первой калитки для стыкованного
 * профиля; провайдер, устанавливающий личность сам, получает nil.
 */
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

// allowed -- проверка членства на входе. Правила совпадения общие с допуском
// профиля (gate.groups): разъехавшись, они дали бы вход, который каталог
// разрешил, а калитка тут же отвергла.
func allowed(groups, want []string) bool {
	return config.GroupsAllow(groups, want)
}
