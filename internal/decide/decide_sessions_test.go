package decide

/*
 * Секция sessions и внешние провайдеры: своя сессия в аудит, чужой JWT по
 * схеме claims, кука приложения по списку доверенных.
 */

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/learn"
	"github.com/exemt/placitum-auth/internal/protocol"
)

// Своя сессия едет в аудит: источник, вид own, субъект, sid и группы.
func TestAllowReportsOwnSession(t *testing.T) {
	p := profile(t, "")

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, nil)

	res := Check(in, key, nil)

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions: %+v", res.Sessions)
	}

	s := res.Sessions[0]
	if s.Source != "default" || s.Kind != protocol.SessionOwn || s.User != "ivanov" ||
		s.ID != "sid-1" || !s.Verified || s.Issued != now.Unix() ||
		s.Expires != now.Add(8*time.Hour).Unix() || len(s.Groups) != 1 || s.Groups[0] != "ops" {
		t.Fatalf("session: %+v", s)
	}

	// Без сессии секции нет: allow без неё и allow с ней -- разные записи.
	if res := Check(input(p, "GET", "/cart"), key, nil); len(res.Sessions) != 0 {
		t.Fatalf("gate without a session reported %+v", res.Sessions)
	}
}

const jwtSourceYAML = `
login:
  uri: /login
provider: jwt
providers:
  jwt:
    cookie: access_token
    verify: { alg: HS256, secret_env: WAF_TEST_JWT_SECRET, issuer: idp, leeway: 30s }
    claims: { groups: groups }
`

// external собирает профиль на внешнем источнике: ключ проверки подставляется
// напрямую, как его подставил бы загрузчик из файла или окружения.
func external(t *testing.T, yaml string, secret []byte) *config.Profile {
	t.Helper()

	src, err := config.ParseSource("ext", []byte(yaml))
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate source: %v", err)
	}

	if src.Providers.JWT != nil {
		src.Providers.JWT.Key = secret
	}

	p := profile(t, "")
	p.Src = src

	return p
}

func hs256(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()

	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}

		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signing := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))

	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestJWTCookieOpensSession(t *testing.T) {
	p := external(t, jwtSourceYAML, []byte("s3cret"))

	in := input(p, "GET", "/cart")
	in.Cookie = hs256(t, map[string]any{
		"sub": "alice", "sid": "s-1", "iss": "idp",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"groups": []string{"ops", "dev"},
	}, "s3cret")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q findings %+v", res.Verdict, res.Code, res.Findings)
	}

	if res.Headers["X-WAF-User"] != "alice" || res.Headers["X-WAF-Groups"] != "ops,dev" ||
		res.Headers["X-WAF-Auth"] != "jwt" {
		t.Fatalf("headers: %+v", res.Headers)
	}

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions: %+v", res.Sessions)
	}

	s := res.Sessions[0]
	if s.Source != "ext" || s.Kind != protocol.SessionJWT || s.User != "alice" || s.ID != "s-1" ||
		!s.Verified || s.Issued != now.Unix() || s.Expires != now.Add(time.Hour).Unix() {
		t.Fatalf("session: %+v", s)
	}
}

func TestJWTRejections(t *testing.T) {
	p := external(t, jwtSourceYAML, []byte("s3cret"))

	cases := map[string]struct {
		token string
		code  string
	}{
		"foreign key": {
			hs256(t, map[string]any{"sub": "alice", "iss": "idp"}, "other"), CodeSessionBad},
		"expired": {
			hs256(t, map[string]any{"sub": "alice", "iss": "idp",
				"exp": now.Add(-time.Minute).Unix()}, "s3cret"), CodeSessionExpired},
		"foreign issuer": {
			hs256(t, map[string]any{"sub": "alice", "iss": "someone"}, "s3cret"), CodeSessionSource},
		"not a token": {"garbage", CodeSessionBad},
	}

	for name, c := range cases {
		in := input(p, "POST", "/api/orders")
		in.Cookie = c.token

		res := Check(in, key, nil)

		if res.Verdict != protocol.VerdictDeny || res.Code != c.code {
			t.Fatalf("%s: verdict %q code %q, want deny %q", name, res.Verdict, res.Code, c.code)
		}

		if len(res.Sessions) != 0 {
			t.Fatalf("%s: rejected token reported a session %+v", name, res.Sessions)
		}
	}

	// Допуск leeway: exp секунду назад -- ещё жив.
	in := input(p, "GET", "/cart")
	in.Cookie = hs256(t, map[string]any{"sub": "alice", "iss": "idp",
		"exp": now.Add(-time.Second).Unix()}, "s3cret")

	if res := Check(in, key, nil); res.Verdict != protocol.VerdictAllow {
		t.Fatalf("leeway: %q %q", res.Verdict, res.Code)
	}
}

// Без ключа claims написал клиент: сессия открывается, но verified: false.
func TestJWTUnverifiedParse(t *testing.T) {
	p := external(t, `
provider: jwt
providers:
  jwt:
    cookie: access_token
    verify: { alg: none }
`, nil)

	in := input(p, "GET", "/cart")
	in.Cookie = hs256(t, map[string]any{"sub": "alice"}, "whatever")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || len(res.Sessions) != 1 ||
		res.Sessions[0].Verified || res.Sessions[0].User != "alice" {
		t.Fatalf("unverified: %q %+v", res.Verdict, res.Sessions)
	}

	// Ни sid, ни jti -- идентификатор из отпечатка токена.
	if res.Sessions[0].ID == "" || res.Sessions[0].ID[:7] != "sha256:" {
		t.Fatalf("id: %q", res.Sessions[0].ID)
	}

	// Без login.uri навигации некуда идти: 401 и ей.
	if res := Check(input(p, "GET", "/cart"), key, nil); res.Verdict != protocol.VerdictDeny ||
		res.Code != CodeNoSession {
		t.Fatalf("no login.uri: %q %q", res.Verdict, res.Code)
	}
}

func TestJWTBearerHeader(t *testing.T) {
	p := external(t, `
login:
  uri: /login
provider: jwt
providers:
  jwt:
    header: authorization
    prefix: "Bearer "
    verify: { alg: HS256, secret_env: WAF_TEST_JWT_SECRET }
`, []byte("s3cret"))

	in := input(p, "GET", "/cart")
	in.Headers = []protocol.Header{{"Authorization",
		"bearer " + hs256(t, map[string]any{"sub": "bob", "jti": "j-9"}, "s3cret")}}

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || len(res.Sessions) != 1 ||
		res.Sessions[0].User != "bob" || res.Sessions[0].ID != "j-9" {
		t.Fatalf("bearer: %q %+v", res.Verdict, res.Sessions)
	}

	// Схема не та -- токена нет.
	in.Headers = []protocol.Header{{"Authorization", "Basic abc"}}

	if res := Check(in, key, nil); res.Verdict != protocol.VerdictRedirect ||
		res.Code != CodeNoSession {
		t.Fatalf("basic: %q %q", res.Verdict, res.Code)
	}
}

// Навигация без сессии на внешнем источнике уходит на страницу входа
// приложения как есть: ни билета, ни ?rd= она не поймёт.
func TestExternalRedirectHasNoTicket(t *testing.T) {
	p := external(t, jwtSourceYAML, []byte("s3cret"))

	res := Check(input(p, "GET", "/cart"), key, nil)

	if res.Verdict != protocol.VerdictRedirect || res.RedirectURL != "/login" ||
		len(res.Cookies) != 0 || res.RedirectStatus != 303 {
		t.Fatalf("redirect: %+v", res)
	}
}

const appSourceYAML = `
login:
  uri: /login
provider: app
list:
  sessions: shop_sessions
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      logout: { uri: /api/logout }
      user: { from: body.form, field: username }
`

func TestAppCookieTrustedByList(t *testing.T) {
	p := external(t, appSourceYAML, nil)

	id := learn.Hash("app-cookie-value")
	mirror := lists{ready: true, ids: map[string]bool{id: true},
		reasons: map[string]string{id: "AUTH_LOGIN alice"}}

	in := input(p, "GET", "/cart")
	in.Cookie = "app-cookie-value"

	res := Check(in, key, mirror)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if res.Headers["X-WAF-User"] != "alice" || res.Headers["X-WAF-Auth"] != "app" {
		t.Fatalf("headers: %+v", res.Headers)
	}

	if len(res.Sessions) != 1 || res.Sessions[0].Kind != protocol.SessionApp ||
		res.Sessions[0].User != "alice" || res.Sessions[0].ID != id || !res.Sessions[0].Verified {
		t.Fatalf("sessions: %+v", res.Sessions)
	}
}

func TestAppCookieUntrusted(t *testing.T) {
	p := external(t, appSourceYAML, nil)

	in := input(p, "GET", "/cart")
	in.Cookie = "unknown-cookie"

	empty := lists{ready: true, ids: map[string]bool{}}

	// Кука есть, записи нет: как без сессии -- навигацию на вход приложения.
	res := Check(in, key, empty)
	if res.Verdict != protocol.VerdictRedirect || res.RedirectURL != "/login" ||
		res.Code != CodeNoSession || len(res.Sessions) != 0 {
		t.Fatalf("unlisted: %+v", res)
	}

	post := input(p, "POST", "/api/orders")
	post.Cookie = "unknown-cookie"

	if res := Check(post, key, empty); res.Verdict != protocol.VerdictDeny ||
		res.Code != CodeNoSession {
		t.Fatalf("unlisted post: %q %q", res.Verdict, res.Code)
	}

	// Списка не видно -- ни закрыто, ни открыто: чужую сессию не подтвердить и
	// не опровергнуть, и метод запроса тут ничего не меняет.
	if res := Check(in, key, lists{ready: false}); res.Verdict != protocol.VerdictError ||
		res.Code != CodeListUnavailable {
		t.Fatalf("list down: %q %q", res.Verdict, res.Code)
	}

	if res := Check(post, key, lists{ready: false}); res.Verdict != protocol.VerdictError ||
		res.Code != CodeListUnavailable {
		t.Fatalf("list down post: %q %q", res.Verdict, res.Code)
	}

	if res := Check(post, key, nil); res.Code != CodeListUnavailable {
		t.Fatalf("no mirror: %q", res.Code)
	}
}

// Адреса входа и выхода приложения -- свои: POST формы приходит без
// доверенной куки по построению.
func TestAppLoginPathsAreOwn(t *testing.T) {
	p := external(t, appSourceYAML, nil)
	empty := lists{ready: true, ids: map[string]bool{}}

	for _, uri := range []string{"/api/login", "/api/logout", "/login"} {
		res := Check(input(p, "POST", uri), key, empty)

		if res.Verdict != protocol.VerdictAllow || res.Code != CodeSelf {
			t.Fatalf("%s: %q %q", uri, res.Verdict, res.Code)
		}
	}

	if res := Check(input(p, "POST", "/api/orders"), key, empty); res.Verdict != protocol.VerdictDeny {
		t.Fatalf("foreign path: %q", res.Verdict)
	}
}
