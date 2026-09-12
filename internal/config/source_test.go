package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalSource = `
login:
  uri: /waf/login
provider: local
providers:
  local:
    users: users.yaml
`

func TestSourceDefaultsSurviveParsing(t *testing.T) {
	src, err := ParseSource("default", []byte(minimalSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Умолчание куки -- на источник: источник и есть пространство сессий,
	// поэтому без явного имени источники изолированы друг от друга.
	if src.Session.Cookie != "waf_sid_default" || src.Ticket.Cookie != "waf_lgn_default" {
		t.Fatalf("cookie defaults lost: %+v", src.Session)
	}

	if src.Session.TTL.D() != 8*time.Hour {
		t.Fatalf("ttl default lost: %s", src.Session.TTL.D())
	}

	if src.Lockout.Attempts != 5 || src.Roster.Prefix != "auth:" {
		t.Fatalf("lockout/roster defaults lost: %+v %+v", src.Lockout, src.Roster)
	}
}

// Опечатка в имени поля -- ошибка загрузки, а не молча выигравшее умолчание.
func TestSourceUnknownFieldIsRejected(t *testing.T) {
	_, err := ParseSource("default", []byte(minimalSource+"\nsesion:\n  ttl: 1h\n"))
	if err == nil {
		t.Fatal("a misspelled key was accepted")
	}
}

func TestSourceValidationRejects(t *testing.T) {
	cases := map[string]string{
		"относительный login.uri": "\nlogin:\n  uri: waf/login\n",
		"пустой провайдер":        "\nprovider: \"\"\n",
		"неизвестный провайдер":   "\nprovider: kerberos\n",
		"from не для totp":        "\nidentity:\n  from: other\n",
		"одинаковые cookie":       "\nsession:\n  cookie: waf_x\nticket:\n  cookie: waf_x\n",
		"продление длиннее срока": "\nsession:\n  ttl: 1h\n  renew_after: 2h\n",
		"чужая привязка":          "\nsession:\n  bind: [asn]\n",
		"roster не тот":           "\nroster:\n  store: memcached\n",
	}

	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			src, err := ParseSource("default", []byte(minimalSource+extra))
			if err != nil {
				return // отвергнут уже разбором -- тоже отказ
			}

			if err := src.Validate(); err == nil {
				t.Fatalf("source was accepted: %s", extra)
			}
		})
	}
}

// Источник без формы не способен никого впустить -- и не грузится. Прежние
// профили-спутники в новой модели живут профилем на чужом источнике.
func TestSourceNeedsForm(t *testing.T) {
	src, err := ParseSource("default", []byte(
		"provider: local\nproviders:\n  local:\n    users: users.yaml\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err == nil {
		t.Fatal("a source without login.uri was accepted")
	}
}

/*
 * TOTP берёт личность из сессии первого источника (identity.from) и секрет из
 * файла пользователей. Без любого из двух это форма, у которой некого
 * спрашивать секрет, и обнаружиться это обязано при загрузке.
 */
func TestTOTPNeedsIdentityFrom(t *testing.T) {
	raw := `
login:
  uri: /waf/login
provider: code
providers:
  code:
    kind: totp
    digits: 6
    period: 30s
    skew: 1
    users: users.yaml
`

	src, err := ParseSource("default", []byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = src.Validate()
	if err == nil || !strings.Contains(err.Error(), "identity.from") {
		t.Fatalf("validate: %v", err)
	}

	// С identity.from тот же источник проходит; сам на себя ссылаться нельзя.
	src, err = ParseSource("totp", []byte(raw+"identity:\n  from: default\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate with from: %v", err)
	}

	// Куки стыкованного источника отличаются от первого без всякого хака:
	// умолчания и так на источник, waf_sid_totp против waf_sid_default.
	if src.Session.Cookie != "waf_sid_totp" || src.Ticket.Cookie != "waf_lgn_totp" {
		t.Fatalf("stacked cookies not per-source: %s %s", src.Session.Cookie, src.Ticket.Cookie)
	}

	src, _ = ParseSource("default", []byte(raw+"identity:\n  from: default\n"))
	if err := src.Validate(); err == nil {
		t.Fatal("self-referencing identity.from accepted")
	}
}

func TestLDAPGroupsNeedSearch(t *testing.T) {
	raw := strings.Replace(minimalSource, "provider: local", "provider: ldap", 1) + `
  ldap:
    url: ldaps://dc.example.com:636
    bind: upn
    upn_suffix: "@example.com"
    groups: ["CN=Users,DC=example,DC=com"]
`

	src, err := ParseSource("default", []byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err == nil {
		t.Fatal("groups without bind: search were accepted")
	}
}

func TestUsersRejectPlainPasswords(t *testing.T) {
	_, err := ParseUsers([]byte("users:\n  - login: ivanov\n    password: hunter2\n"))
	if err == nil {
		t.Fatal("a plain password was accepted")
	}

	users, err := ParseUsers([]byte("users:\n  - login: Ivanov\n" +
		"    password: \"$2a$12$RfCieXmylFauGSITCrA8L.Fx32uDoODW.7bsi4lG6eSIh5taEOzu6\"\n"))
	if err != nil {
		t.Fatalf("parse users: %v", err)
	}

	// Ключ -- логин в нижнем регистре: каталоги и люди регистр не различают.
	if _, ok := users["ivanov"]; !ok {
		t.Fatalf("login was not folded: %v", users)
	}

	if !users["ivanov"].Active() {
		t.Fatal("enabled must default to true")
	}
}

func TestDuplicateLoginIsRejected(t *testing.T) {
	const hash = "$2a$12$RfCieXmylFauGSITCrA8L.Fx32uDoODW.7bsi4lG6eSIh5taEOzu6"

	_, err := ParseUsers([]byte("users:\n" +
		"  - login: ivanov\n    password: \"" + hash + "\"\n" +
		"  - login: IVANOV\n    password: \"" + hash + "\"\n"))
	if err == nil {
		t.Fatal("a duplicate login was accepted")
	}
}

/*
 * Своя форма входа приезжает файлом рядом с источником. Разбирается она при
 * чтении снапшота: битый шаблон обязан отвергнуть поколение целиком, а не
 * дождаться пользователя, который до формы дойдёт.
 */
func TestLoginPageFromSourceDir(t *testing.T) {
	dir := t.TempDir()
	page := "<form method=\"post\"><input name=\"csrf\" value=\"{{.Nonce}}\"></form>"

	write := func(name, body string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("login.html", page)

	src, err := ParseSource("default", []byte(minimalSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := attachLoginPage(src, dir); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if src.LoginPage == nil {
		t.Fatal("login.html is present, but the source has no page")
	}

	write("login.html", "{{if .Nonce}}")

	broken, err := ParseSource("default", []byte(minimalSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := attachLoginPage(broken, dir); err == nil {
		t.Fatal("a broken template was accepted")
	}

	if err := os.Remove(filepath.Join(dir, "login.html")); err != nil {
		t.Fatalf("remove: %v", err)
	}

	plain, err := ParseSource("default", []byte(minimalSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := attachLoginPage(plain, dir); err != nil {
		t.Fatalf("attach without a page: %v", err)
	}

	if plain.LoginPage != nil {
		t.Fatal("no file, but the source got a page")
	}
}

/* --- внешние провайдеры: jwt и app ----------------------------------------- */

const jwtSource = `
provider: jwt
providers:
  jwt:
    cookie: access_token
    verify: { alg: HS256, secret_env: WAF_JWT_SECRET }
`

// У внешнего источника формы нет: login.uri необязателен, а claims получают
// имена RFC 7519 по умолчанию.
func TestJWTSourceDefaults(t *testing.T) {
	src, err := ParseSource("idp", []byte(jwtSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if !src.External() || src.Learns() || src.SessionCookie() != "access_token" {
		t.Fatalf("shape: external=%v learns=%v cookie=%q", src.External(), src.Learns(),
			src.SessionCookie())
	}

	c := src.Providers.JWT.Claims
	if c.User != "sub" || c.Session != "sid" || c.Issued != "iat" || c.Expiry != "exp" {
		t.Fatalf("claim defaults: %+v", c)
	}
}

func TestJWTSourceRejects(t *testing.T) {
	cases := map[string]string{
		"кука и заголовок сразу": `
provider: jwt
providers:
  jwt:
    cookie: a
    header: authorization
    verify: { alg: HS256, secret_env: S }
`,
		"ни куки, ни заголовка": `
provider: jwt
providers:
  jwt:
    verify: { alg: HS256, secret_env: S }
`,
		"HS256 без ключа": `
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: HS256 }
`,
		"none с ключом": `
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: none, secret_env: S }
`,
		"RS256 с секретом из окружения": `
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: RS256, secret_env: S }
`,
		"два источника ключа": `
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: HS256, secret_env: S, key_file: k.pem }
`,
		"неизвестный алгоритм": `
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: PS256, key_file: k.pem }
`,
		"относительный login.uri": `
login:
  uri: login
provider: jwt
providers:
  jwt:
    cookie: a
    verify: { alg: none }
`,
		"секция провайдера отсутствует": `
provider: jwt
`,
	}

	for name, raw := range cases {
		src, err := ParseSource("idp", []byte(raw))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}

		if err := src.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

const appSource = `
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
      user: { from: body.json, field: user.email }
`

func TestAppSourceDefaults(t *testing.T) {
	src, err := ParseSource("shop", []byte(appSource))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if !src.External() || !src.Learns() || src.SessionCookie() != "JSESSIONID" {
		t.Fatalf("shape: external=%v learns=%v cookie=%q", src.External(), src.Learns(),
			src.SessionCookie())
	}

	l := src.Providers.App.Learn
	if l.Login.Method != "POST" || len(l.Success.Status) != 3 || !l.Success.RequiresCookieNew() {
		t.Fatalf("learn defaults: %+v", l)
	}

	// Список обязателен, и его срок -- срок сессии.
	if src.List.TTL != src.Session.TTL {
		t.Fatalf("list ttl: %s", src.List.TTL.D())
	}
}

func TestAppSourceRejects(t *testing.T) {
	cases := map[string]string{
		"без списка": `
provider: app
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      user: { from: body.form, field: u }
`,
		"без куки": `
provider: app
list: { sessions: s }
providers:
  app:
    learn:
      login: { uri: /api/login }
      user: { from: body.form, field: u }
`,
		"без адреса входа": `
provider: app
list: { sessions: s }
providers:
  app:
    cookie: JSESSIONID
    learn:
      user: { from: body.form, field: u }
`,
		"неизвестный источник логина": `
provider: app
list: { sessions: s }
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      user: { from: cookie, field: u }
`,
		"без имени поля": `
provider: app
list: { sessions: s }
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      user: { from: args }
`,
		"кука совпадает с кукой списка": `
provider: app
list: { sessions: s, cookie: JSESSIONID }
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      user: { from: args, field: u }
`,
		"выход со строкой запроса": `
provider: app
list: { sessions: s }
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      logout: { uri: "/api/logout?all=1" }
      user: { from: args, field: u }
`,
		"json без пути": `
provider: app
list: { sessions: s }
providers:
  app:
    cookie: JSESSIONID
    learn:
      login: { uri: /api/login }
      success: { json: { equals: "true" } }
      user: { from: args, field: u }
`,
	}

	for name, raw := range cases {
		src, err := ParseSource("shop", []byte(raw))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}

		if err := src.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Адреса входа и выхода приложения -- свои у профиля на таком источнике.
func TestAppProfileOwnsLoginPaths(t *testing.T) {
	src, err := ParseSource("shop", []byte(appSource+"      logout: { uri: /api/logout }\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	p := &Profile{Src: src}

	for _, uri := range []string{"/api/login", "/api/logout", "/login", "/login/reset"} {
		if !p.OwnPath(uri) {
			t.Fatalf("%s must be own", uri)
		}
	}

	if p.OwnPath("/api/login/other") || p.OwnPath("/cart") {
		t.Fatal("foreign paths must not be own")
	}
}
