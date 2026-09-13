package decide

import (
	"strings"
	"testing"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/token"
)

var key = mustKey()

func mustKey() *token.Key {
	k, err := token.NewKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}

	return k
}

const sourceYAML = `
login:
  uri: /waf/login
session:
  ttl: 8h
  renew_after: 1h
  bind: [subnet, ua]
provider: code
providers:
  code:
    kind: static
    codes: ["$2a$12$SMWBrvxLC2rBY9pNJ4CLnuEpfgTg63XlN16a8Wn59AseYuLNXR4V6"]
`

func source(t *testing.T, name, extra string) *config.Source {
	t.Helper()

	src, err := config.ParseSource(name, []byte(sourceYAML+extra))
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("validate source: %v", err)
	}

	return src
}

const profileYAML = `
mode: enforce
source: default
`

// profile собирает калитку с уже разрешённым источником -- так, как это делает
// реестр. extra с mode: замещает режим целиком.
func profile(t *testing.T, extra string) *config.Profile {
	t.Helper()

	raw := profileYAML + extra

	if strings.Contains(extra, "mode:") {
		raw = strings.Replace(profileYAML, "mode: enforce", "", 1) + extra
	}

	p, err := config.ParseProfile("default", []byte(raw))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate profile: %v", err)
	}

	p.Src = source(t, "default", "")

	return p
}

// lists -- зеркало активного списка для тестов. ready=false изображает
// зеркало без снапшота: списка не видно, решать нельзя.
type lists struct {
	ready   bool
	ids     map[string]bool
	reasons map[string]string
}

func (l lists) Contains(_, sid string) (ok, ready bool) { return l.ids[sid], l.ready }

func (l lists) Lookup(_, sid string) (livelist.Entry, bool, bool) {
	return livelist.Entry{Reason: l.reasons[sid]}, l.ids[sid], l.ready
}

var now = time.Unix(1_700_000_000, 0)

func input(p *config.Profile, method, uri string) Input {
	return Input{
		Profile:  p,
		Ask:      "default",
		Method:   method,
		URI:      uri,
		ClientIP: "203.0.113.42",
		Accept:   "text/html,application/xhtml+xml",
		Now:      now,
	}
}

func session(t *testing.T, src *config.Source, mutate func(*token.Session)) string {
	t.Helper()

	s := &token.Session{
		SID:    "sid-1",
		Sub:    "ivanov",
		Issued: now.Unix(),
		Expiry: now.Add(8 * time.Hour).Unix(),
		Renew:  now.Add(time.Hour).Unix(),
		// Scope -- имя куки источника, Iss -- сам источник: токен привязан к
		// обоим, и профили чужих источников его не принимают.
		Scope:  src.Session.Cookie,
		Iss:    src.Name,
		Net:    token.Subnet("203.0.113.42", 24, 64),
		AMR:    []string{"pwd", "totp"},
		Groups: []string{"ops"},
	}

	if mutate != nil {
		mutate(s)
	}

	raw, err := key.SealSession(s)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	return raw
}

/*
 * Главная развилка: навигационный GET уводят на форму, всё остальное получает
 * 401. Именно она отличает калитку от сломанного фронтенда, поэтому проверяется
 * таблицей, а не одним случаем.
 */
func TestGateWithoutSession(t *testing.T) {
	p := profile(t, "")

	cases := []struct {
		name    string
		method  string
		uri     string
		accept  string
		dest    string
		verdict string
	}{
		{"навигация", "GET", "/cart", "text/html", "", protocol.VerdictRedirect},
		{"HEAD", "HEAD", "/cart", "text/html", "", protocol.VerdictRedirect},
		{"POST теряет тело", "POST", "/cart", "text/html", "", protocol.VerdictDeny},
		{"PATCH", "PATCH", "/cart", "text/html", "", protocol.VerdictDeny},
		{"XHR без html", "GET", "/cart", "application/json", "", protocol.VerdictDeny},
		{"без Accept", "GET", "/cart", "", "", protocol.VerdictDeny},
		// Не браузер (curl, fetch из node): Sec-Fetch-Dest нет, решает Accept.
		{"curl со всем подряд", "GET", "/cart", "*/*", "", protocol.VerdictRedirect},
		{"переход браузера", "GET", "/cart", "text/html,*/*;q=0.8", "document", protocol.VerdictRedirect},
		{"фрейм", "GET", "/cart", "text/html,*/*;q=0.8", "iframe", protocol.VerdictRedirect},
		// favicon.ico без сессии: редирект перевыпустил бы билет открытой формы.
		{"favicon", "GET", "/favicon.ico", "image/avif,image/webp,*/*;q=0.8", "image", protocol.VerdictDeny},
		{"fetch страницы со всем подряд", "GET", "/api/x", "*/*", "empty", protocol.VerdictDeny},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(p, c.method, c.uri)
			in.Accept = c.accept
			in.SecFetchDest = c.dest

			res := Check(in, key, nil)

			if res.Verdict != c.verdict {
				t.Fatalf("verdict %q, want %q (code %s)", res.Verdict, c.verdict, res.Code)
			}

			if res.Verdict == protocol.VerdictDeny && res.Response != "auth_required" {
				t.Fatalf("deny response %q, want auth_required", res.Response)
			}
		})
	}
}

// Билет ставится вместе с редиректом -- единственный вердикт, кроме отказа, на
// котором модуль применяет секцию cookies.
func TestRedirectCarriesTicket(t *testing.T) {
	p := profile(t, "")

	in := input(p, "GET", "/cart")
	in.Args = "page=2"

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictRedirect {
		t.Fatalf("verdict %q", res.Verdict)
	}

	if res.RedirectStatus != 303 {
		t.Fatalf("status %d, want 303", res.RedirectStatus)
	}

	if !strings.HasPrefix(res.RedirectURL, "/waf/login?rd=") {
		t.Fatalf("target %q", res.RedirectURL)
	}

	if !strings.Contains(res.RedirectURL, "page%3D2") {
		t.Fatalf("query string was lost: %q", res.RedirectURL)
	}

	if len(res.Cookies) != 1 || res.Cookies[0].Name != "waf_lgn_default" {
		t.Fatalf("ticket cookie is missing: %+v", res.Cookies)
	}

	if res.Cookies[0].Path != "/waf/login" {
		t.Fatalf("ticket path %q: it must not travel with every request",
			res.Cookies[0].Path)
	}

	ticket, err := key.OpenTicket(res.Cookies[0].Value, now)
	if err != nil {
		t.Fatalf("ticket does not verify: %v", err)
	}

	// Scope билета -- имя источника: форма принадлежит ему.
	if ticket.Return != "/cart?page=2" || ticket.Scope != "default" {
		t.Fatalf("ticket carries %+v", ticket)
	}
}

func TestAllowSetsIdentityHeaders(t *testing.T) {
	p := profile(t, "")

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, nil)

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	want := map[string]string{
		"X-WAF-User":   "ivanov",
		"X-WAF-Groups": "ops",
		"X-WAF-Auth":   "pwd+totp",
	}

	for name, value := range want {
		if res.Headers[name] != value {
			t.Fatalf("header %s = %q, want %q", name, res.Headers[name], value)
		}
	}
}

/*
 * Заголовки личности ставятся всегда, даже когда личности нет: unset на фазе
 * запроса модуль не поддерживает, и пропуск пустого значения оставил бы
 * приложению X-WAF-User, который клиент выбрал себе сам.
 *
 * Проверяется на allow без сессии -- наблюдение: только там вердикт allow
 * встречается с пустой личностью при живом источнике.
 */
func TestAllowOverwritesSpoofedHeaders(t *testing.T) {
	p := profile(t, "\nmode: observe\n")

	res := Check(input(p, "GET", "/cart"), key, nil)

	if res.Verdict != protocol.VerdictAllow {
		t.Fatalf("verdict = %v, want allow", res.Verdict)
	}

	for _, name := range []string{"X-WAF-User", "X-WAF-Groups", "X-WAF-Auth"} {
		value, ok := res.Headers[name]
		if !ok {
			t.Fatalf("header %s is missing on an allow without a session", name)
		}

		if value != "" {
			t.Fatalf("header %s = %q, want empty", name, value)
		}
	}
}

func TestSessionRejections(t *testing.T) {
	p := profile(t, "")

	cases := []struct {
		name   string
		cookie func() string
		code   string
	}{
		{
			name: "истёк",
			cookie: func() string {
				return session(t, p.Src, func(s *token.Session) { s.Expiry = now.Add(-time.Minute).Unix() })
			},
			code: CodeSessionExpired,
		},
		{
			name:   "чужая подсеть",
			cookie: func() string { return session(t, p.Src, func(s *token.Session) { s.Net = "198.51.100.0/24" }) },
			code:   CodeSessionBind,
		},
		{
			name:   "чужая кука",
			cookie: func() string { return session(t, p.Src, func(s *token.Session) { s.Scope = "waf_sid_admin" }) },
			code:   CodeSessionScope,
		},
		{
			/*
			 * Кука совпала, источник -- нет: так выглядела бы попытка склеить
			 * два источника одним именем куки. Реестр такое поколение не
			 * принимает, а штамп iss не даёт дыре открыться даже в окно, пока
			 * где-то живёт старый конфиг.
			 */
			name:   "чужой источник",
			cookie: func() string { return session(t, p.Src, func(s *token.Session) { s.Iss = "ldap" }) },
			code:   CodeSessionSource,
		},
		{
			name:   "подделана",
			cookie: func() string { return session(t, p.Src, nil) + "x" },
			code:   CodeSessionBad,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(p, "POST", "/cart")
			in.Cookie = c.cookie()

			res := Check(in, key, nil)

			if res.Verdict != protocol.VerdictDeny {
				t.Fatalf("verdict %q, want deny", res.Verdict)
			}

			if res.Code != c.code {
				t.Fatalf("code %q, want %q", res.Code, c.code)
			}
		})
	}
}

/*
 * Механизм "кука и список": подпись доказывает выдачу, запись в списке --
 * что сессию не завершили. Четыре исхода: запись есть -- живёт, записи нет --
 * завершена, списка не видно -- закрыто, свежая -- едет на одной подписи,
 * пока запись идёт через секвенсор.
 */
func TestSessionListTruth(t *testing.T) {
	p := profile(t, "")
	p.Src = source(t, "default", `
list:
  sessions: auth_sessions
`)

	aged := func(s *token.Session) { s.Issued = now.Add(-time.Hour).Unix() }

	cases := []struct {
		name    string
		mirror  Sessions
		mutate  func(*token.Session)
		verdict string
		code    string
	}{
		{
			name:    "в списке",
			mirror:  lists{ready: true, ids: map[string]bool{"sid-1": true}},
			mutate:  aged,
			verdict: protocol.VerdictAllow,
			code:    CodeOK,
		},
		{
			name:    "записи нет -- завершена",
			mirror:  lists{ready: true},
			mutate:  aged,
			verdict: protocol.VerdictDeny,
			code:    CodeSessionRevoked,
		},
		{
			// Ни закрыто, ни открыто: жив ли вход, сказать нечем, и решает это
			// waf_exception маршрута, а не калитка.
			name:    "списка не видно -- проверить нечем",
			mirror:  lists{ready: false},
			mutate:  aged,
			verdict: protocol.VerdictError,
			code:    CodeListUnavailable,
		},
		{
			name:    "зеркала нет вовсе -- проверить нечем",
			mirror:  nil,
			mutate:  aged,
			verdict: protocol.VerdictError,
			code:    CodeListUnavailable,
		},
		{
			name:    "свежая едет по подписи",
			mirror:  lists{ready: true},
			verdict: protocol.VerdictAllow,
			code:    CodeOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(p, "POST", "/cart")
			in.Cookie = session(t, p.Src, c.mutate)

			res := Check(in, key, c.mirror)

			if res.Verdict != c.verdict || res.Code != c.code {
				t.Fatalf("verdict %q code %q, want %q %q",
					res.Verdict, res.Code, c.verdict, c.code)
			}
		})
	}
}

func TestRenewOnNavigation(t *testing.T) {
	p := profile(t, "")

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Renew = now.Add(-time.Minute).Unix()
	})

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictRedirect || res.Code != CodeRenew {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if !strings.HasPrefix(res.RedirectURL, "/waf/login/renew?rd=") {
		t.Fatalf("target %q", res.RedirectURL)
	}

	// Продление не должно ломать API: у профиля-спутника (пустые
	// redirect_methods, тот же источник) живая сессия отвечает allow, а не
	// редиректом на /renew вместо ответа.
	api := input(companion(t, p), "GET", "/api/orders")
	api.Cookie = in.Cookie

	if res := Check(api, key, nil); res.Verdict != protocol.VerdictAllow {
		t.Fatalf("api verdict %q, want allow", res.Verdict)
	}
}

// companion -- профиль-спутник для путей API: тот же источник (общее
// пространство сессий), пустые redirect_methods -- без сессии всегда 401.
func companion(t *testing.T, of *config.Profile) *config.Profile {
	t.Helper()

	p, err := config.ParseProfile("api", []byte(
		"mode: enforce\nsource: "+of.Source+"\ngate:\n  redirect_methods: []\n"))
	if err != nil {
		t.Fatalf("parse companion: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate companion: %v", err)
	}

	p.Src = of.Src

	return p
}

/*
 * Пути API -- профиль-спутник, а не список путей в главном профиле: без сессии
 * он отвечает 401 на всё, даже на навигационный GET, а сессию главной калитки
 * принимает -- источник общий. Профиль чужого источника ту же сессию отвергает.
 */
func TestCompanionSharesSource(t *testing.T) {
	p := profile(t, "")
	api := companion(t, p)

	res := Check(input(api, "GET", "/api/orders"), key, nil)
	if res.Verdict != protocol.VerdictDeny || res.Code != CodeNoSession {
		t.Fatalf("no session: verdict %q code %q, want deny", res.Verdict, res.Code)
	}

	in := input(api, "GET", "/api/orders")
	in.Cookie = session(t, p.Src, nil)

	if res := Check(in, key, nil); res.Verdict != protocol.VerdictAllow {
		t.Fatalf("shared source: verdict %q code %q, want allow", res.Verdict, res.Code)
	}

	// Чужой источник -- чужая вселенная: сессия default не открывает профиль
	// на источнике admin, сколько бы общего ключа у них ни было.
	admin, err := config.ParseProfile("admin", []byte("mode: enforce\nsource: admin\n"))
	if err != nil {
		t.Fatalf("parse admin: %v", err)
	}

	// Умолчания кук -- на источник: у admin это waf_sid_admin/waf_lgn_admin.
	admin.Src = source(t, "admin", "")

	foreign := input(admin, "POST", "/cart")
	foreign.Cookie = session(t, p.Src, nil)

	if res := Check(foreign, key, nil); res.Verdict != protocol.VerdictDeny ||
		res.Code != CodeSessionScope {
		t.Fatalf("foreign source: verdict %q code %q, want %q",
			res.Verdict, res.Code, CodeSessionScope)
	}
}

func TestObserveNeverBlocks(t *testing.T) {
	p := profile(t, "\nmode: observe\n")

	res := Check(input(p, "POST", "/cart"), key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeObserve {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if res.Engine["would_verdict"] != protocol.VerdictDeny || res.Engine["passive"] != true {
		t.Fatalf("engine %v, want would_verdict deny and passive", res.Engine)
	}
}

/* --- допуск по группам ------------------------------------------------------ */

/*
 * gated -- профиль закрытой зоны: тот же источник, что у соседа (одно
 * пространство сессий), и список допуска. Именно эта пара -- «вошёл один раз,
 * пустили не везде» -- ради которой проверка стоит на сессии, а не на входе:
 * своего входа такой профиль не видит вовсе.
 */
func gated(t *testing.T, of *config.Profile, mode string) *config.Profile {
	t.Helper()

	p, err := config.ParseProfile("admin", []byte(
		"mode: "+mode+"\nsource: "+of.Source+"\ngate:\n  groups: [admins]\n"))
	if err != nil {
		t.Fatalf("parse gated: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate gated: %v", err)
	}

	p.Src = of.Src

	return p
}

/*
 * Главный сценарий: сессия источника цела и принимается, но группы допуска у
 * неё нет. Отсюда только отказ -- на форму такого не уводят даже навигационным
 * GET: он там уже был, и второй вход выдал бы ту же сессию с теми же группами.
 */
func TestGroupGateDeniesForeignSession(t *testing.T) {
	p := profile(t, "")
	admin := gated(t, p, "enforce")

	in := input(admin, "GET", "/admin")
	in.Cookie = session(t, p.Src, nil) // группы: ops

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictDeny || res.Code != CodeForbidden {
		t.Fatalf("verdict %q code %q, want deny %s", res.Verdict, res.Code, CodeForbidden)
	}

	if res.Response != "auth_forbidden" {
		t.Fatalf("response %q, want auth_forbidden", res.Response)
	}

	// Заголовков личности на отказе нет: внутрь запрос не идёт.
	if len(res.Headers) != 0 {
		t.Fatalf("headers on deny: %v", res.Headers)
	}

	if len(res.Findings) != 1 || res.Findings[0].Code != FindingForbidden {
		t.Fatalf("findings %+v, want %s", res.Findings, FindingForbidden)
	}

	if !strings.Contains(res.Findings[0].Rule, "ivanov") {
		t.Fatalf("finding rule %q says nothing about the subject", res.Findings[0].Rule)
	}
}

// Член группы проходит той же сессией, и регистр в ней роли не играет:
// каталог отдаёт CN как ему удобно, а список контура пишут руками.
func TestGroupGateAllowsMember(t *testing.T) {
	p := profile(t, "")
	admin := gated(t, p, "enforce")

	for _, groups := range [][]string{{"admins"}, {"ops", "Admins"}} {
		in := input(admin, "GET", "/admin")
		in.Cookie = session(t, p.Src, func(s *token.Session) { s.Groups = groups })

		res := Check(in, key, nil)

		if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
			t.Fatalf("groups %v: verdict %q code %q", groups, res.Verdict, res.Code)
		}

		if res.Headers["X-WAF-Groups"] != strings.Join(groups, ",") {
			t.Fatalf("groups header %q", res.Headers["X-WAF-Groups"])
		}
	}
}

// Без сессии закрытый профиль ведёт себя как обычный: сперва вход, отказ по
// группе -- потом. Иначе тот, кто ещё не входил, получал бы 403 вместо формы.
func TestGroupGateWithoutSessionStillRedirects(t *testing.T) {
	admin := gated(t, profile(t, ""), "enforce")

	res := Check(input(admin, "GET", "/admin"), key, nil)

	if res.Verdict != protocol.VerdictRedirect || res.Code != CodeNoSession {
		t.Fatalf("verdict %q code %q, want redirect", res.Verdict, res.Code)
	}
}

/*
 * Просьба соседа «пропустить» гасит требование входа, но не выдаёт прав:
 * допуск по группам -- разграничение, а не проверка личности, и снимать его
 * действием другого инспектора нельзя.
 */
func TestGroupGateIgnoresSkip(t *testing.T) {
	p := profile(t, "")
	admin := gated(t, p, "enforce")

	in := input(admin, "GET", "/admin")
	in.Cookie = session(t, p.Src, nil)
	in.Prior = []protocol.PriorVerdict{{
		Phase:     protocol.PhaseRequest,
		Inspector: "ip",
		Verdict:   protocol.VerdictAllow,
		Actions: []protocol.Action{{
			Do:    protocol.DoSkip,
			Apply: protocol.ApplyRequest,
		}},
	}}

	if res := Check(in, key, nil); res.Code != CodeForbidden {
		t.Fatalf("code %q, want %s", res.Code, CodeForbidden)
	}
}

// Наблюдение и здесь пропускает всех, называя в аудите то, что сделало бы в
// enforce: выкатить закрытую зону, не заперев в ней людей, можно только так.
func TestGroupGateInObserveOnlyRecords(t *testing.T) {
	p := profile(t, "")
	admin := gated(t, p, "observe")

	in := input(admin, "GET", "/admin")
	in.Cookie = session(t, p.Src, nil)

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeObserve {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if res.Engine["would_verdict"] != protocol.VerdictDeny ||
		res.Engine["would_code"] != CodeForbidden {
		t.Fatalf("engine %v", res.Engine)
	}
}

/* --- просьбы соседей -------------------------------------------------------- */

const reauthRule = `
trigger:
  reauth_after: 5m
  prior:
    - from: "*"
      accept: [reauth]
`

func reauthAsk(from string) []protocol.PriorVerdict {
	return []protocol.PriorVerdict{{
		Phase:     protocol.PhaseRequest,
		Inspector: from,
		Verdict:   protocol.VerdictAllow,
		Actions: []protocol.Action{{
			Do:    protocol.DoReauth,
			Apply: protocol.ApplySession,
			Code:  "SESSION_HIJACK",
		}},
	}}
}

// outcomes достаёт исходы просьб из engine: то, что уедет в kind=inspector.
func outcomes(t *testing.T, res Result) []ActionOutcome {
	t.Helper()

	out, ok := res.Engine["actions"].([]ActionOutcome)
	if !ok {
		t.Fatalf("engine.actions is missing: %+v", res.Engine)
	}

	return out
}

/*
 * Главный сценарий канала: сессия цела, но сосед просит вход заново. Правило
 * есть -- несвежая сессия едет на форму, как будто её нет; API получает отказ
 * с телом, а не редирект.
 */
func TestReauthSendsStaleSessionToLogin(t *testing.T) {
	p := profile(t, reauthRule)

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Issued = now.Add(-10 * time.Minute).Unix()
	})
	in.Prior = reauthAsk("repu")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictRedirect || res.Code != CodeReauth {
		t.Fatalf("verdict %q code %q, want redirect %q", res.Verdict, res.Code, CodeReauth)
	}

	if !strings.HasPrefix(res.RedirectURL, "/waf/login?rd=") {
		t.Fatalf("target %q: reauth is a full login, not /renew", res.RedirectURL)
	}

	got := outcomes(t, res)
	if len(got) != 1 || got[0].Outcome != OutcomeApplied || got[0].From != "repu" {
		t.Fatalf("outcomes %+v", got)
	}

	api := input(p, "POST", "/cart")
	api.Cookie = in.Cookie
	api.Prior = in.Prior

	if res := Check(api, key, nil); res.Verdict != protocol.VerdictDeny ||
		res.Code != CodeReauth || res.Response != "auth_required" {
		t.Fatalf("api: verdict %q code %q response %q", res.Verdict, res.Code, res.Response)
	}
}

/*
 * Свежую сессию просьба не трогает: клиент только что доказал, кто он, а
 * отправитель шлёт действие на каждом запросе и не знает, что вход уже
 * случился. Без отсечки форма превращается в карусель.
 */
func TestReauthSparesFreshSession(t *testing.T) {
	p := profile(t, reauthRule)

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, nil) // issued = now
	in.Prior = reauthAsk("repu")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	// Исход остаётся applied: правило нашлось, просьба принята -- просто на
	// эту сессию она пока не действует.
	if got := outcomes(t, res); len(got) != 1 || got[0].Outcome != OutcomeApplied {
		t.Fatalf("outcomes %+v", got)
	}
}

// Без правила просьба не значит ничего, но исход "нет правила" обязан уехать в
// аудит: молчание в ответ на просьбу и есть тот случай, который потом разбирают.
func TestReauthWithoutRuleIsRecordedSilence(t *testing.T) {
	p := profile(t, "")

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Issued = now.Add(-10 * time.Minute).Unix()
	})
	in.Prior = reauthAsk("repu")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if got := outcomes(t, res); len(got) != 1 || got[0].Outcome != OutcomeNoRule {
		t.Fatalf("outcomes %+v", got)
	}
}

// Правило, суженное поводами, не цепляет просьбу с чужим кодом.
func TestReauthCodesFilter(t *testing.T) {
	p := profile(t, `
trigger:
  prior:
    - from: "*"
      accept: [reauth]
      codes: [CREDENTIAL_STUFFING]
`)

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Issued = now.Add(-10 * time.Minute).Unix()
	})
	in.Prior = reauthAsk("repu") // код SESSION_HIJACK

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if got := outcomes(t, res); len(got) != 1 || got[0].Outcome != OutcomeNoRule {
		t.Fatalf("outcomes %+v", got)
	}
}

// Наблюдение не блокирует и здесь: reauth виден в аудите как would, клиент
// проходит.
func TestReauthInObserveOnlyRecords(t *testing.T) {
	p := profile(t, "\nmode: observe\n"+reauthRule)

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Issued = now.Add(-10 * time.Minute).Unix()
	})
	in.Prior = reauthAsk("repu")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeObserve {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if res.Engine["would_verdict"] != protocol.VerdictRedirect ||
		res.Engine["would_code"] != CodeReauth {
		t.Fatalf("engine %v, want would redirect by reauth", res.Engine)
	}
}

// Продление сессии -- редирект, и наблюдение глушит его как любой другой:
// клиент проходит с сессией как есть, в аудите would redirect по AUTH_RENEW.
func TestRenewInObserveOnlyRecords(t *testing.T) {
	p := profile(t, "\nmode: observe\n")

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Renew = now.Add(-time.Minute).Unix()
	})

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeObserve {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if res.Engine["would_verdict"] != protocol.VerdictRedirect ||
		res.Engine["would_code"] != CodeRenew || res.Engine["renew"] != true {
		t.Fatalf("engine %v, want would redirect by renew", res.Engine)
	}
}

/*
 * Skip действует только по правилу с именем отправителя и гасит требование
 * входа целиком. Заголовки личности при этом перезаписываются пустыми: клиент
 * едет внутрь без имени, а не под тем, которое выбрал себе сам.
 */
func TestSkipSuppressesGate(t *testing.T) {
	p := profile(t, `
trigger:
  prior:
    - from: edge
      accept: [skip]
`)

	skipAsk := func(from string) []protocol.PriorVerdict {
		return []protocol.PriorVerdict{{
			Phase:     protocol.PhaseRequest,
			Inspector: from,
			Verdict:   protocol.VerdictAllow,
			Actions: []protocol.Action{{
				Do:    protocol.DoSkip,
				Apply: protocol.ApplyRequest,
			}},
		}}
	}

	in := input(p, "GET", "/cart")
	in.Prior = skipAsk("edge")

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeSkipped {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}

	if value, ok := res.Headers["X-WAF-User"]; !ok || value != "" {
		t.Fatalf("X-WAF-User = %q, want an empty overwrite", value)
	}

	// Чужой отправитель правило не цепляет: калитка работает как обычно.
	other := input(p, "GET", "/cart")
	other.Prior = skipAsk("someone")

	if res := Check(other, key, nil); res.Verdict != protocol.VerdictRedirect {
		t.Fatalf("verdict %q, want redirect for an unmatched sender", res.Verdict)
	}
}

// Просьба пропустить сильнее просьбы про вход: она включена оператором по
// имени отправителя, то есть это его решение, а не соседа.
func TestSkipSuppressesReauth(t *testing.T) {
	p := profile(t, `
trigger:
  prior:
    - from: "*"
      accept: [reauth]
    - from: edge
      accept: [skip]
`)

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, func(s *token.Session) {
		s.Issued = now.Add(-10 * time.Minute).Unix()
	})
	in.Prior = []protocol.PriorVerdict{
		reauthAsk("repu")[0],
		{
			Phase:     protocol.PhaseRequest,
			Inspector: "edge",
			Verdict:   protocol.VerdictAllow,
			Actions: []protocol.Action{{
				Do:    protocol.DoSkip,
				Apply: protocol.ApplyRequest,
			}},
		},
	}

	res := Check(in, key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}
}

/*
 * Нет такого профиля -- проверки не было. Ни отката на default (он пропускал бы
 * трафик при разъезде тега маршрута с загруженными профилями), ни отказа за
 * чужую ошибку развёртывания: исход выбирает waf_exception класса inspector.
 */
func TestUnknownProfileIsAnError(t *testing.T) {
	res := Check(Input{Ask: "no-such", Method: "GET", URI: "/", Now: now}, key, nil)

	if res.Verdict != protocol.VerdictError || res.Code != CodeUnknownProfile {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}
}

// Профиль mode: off без источника отвечает allow и не трогает ничего.
func TestOffProfileAllows(t *testing.T) {
	p, err := config.ParseProfile("default", []byte("mode: off\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	res := Check(input(p, "POST", "/cart"), key, nil)

	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOff {
		t.Fatalf("verdict %q code %q", res.Verdict, res.Code)
	}
}

func TestReturnPathRejectsForeignTargets(t *testing.T) {
	for _, uri := range []string{
		"//evil.example.com/",
		"http://evil.example.com/",
		`/cart\..\..`,
		"/cart\n/x",
		strings.Repeat("/a", 600),
	} {
		if got := returnPath(uri, ""); got != "" {
			t.Fatalf("returnPath(%q) = %q, want empty", uri, got)
		}
	}

	if got := returnPath("/cart", "a=1"); got != "/cart?a=1" {
		t.Fatalf("returnPath = %q", got)
	}
}

/*
 * Своя форма: страница, POST входа, renew и статика под login.uri. Вход на них
 * -- рекурсия, и инспектор на этой локации отвечает allow до любой лестницы.
 */
func TestOwnPathAllows(t *testing.T) {
	p := profile(t, "")

	for _, uri := range []string{"/waf/login", "/waf/login/renew", "/waf/login/static/x.css"} {
		in := input(p, "POST", uri)
		in.Accept = ""

		res := Check(in, key, nil)

		if res.Verdict != protocol.VerdictAllow || res.Code != CodeSelf {
			t.Fatalf("%s: verdict %s code %s, want allow/%s", uri, res.Verdict, res.Code, CodeSelf)
		}
	}

	if res := Check(input(p, "GET", "/waf/login-other"), key, nil); res.Code == CodeSelf {
		t.Fatalf("/waf/login-other is not the form path, got %s", res.Code)
	}
}

/*
 * gate.inline: тот же билет, что у редиректа, но вердикт deny с записью
 * отказа -- форму положит вызывающий. Запасной адрес редиректа остаётся
 * заполненным: без формы вызывающий отвечает им.
 */
func TestInlineDeniesWithTicket(t *testing.T) {
	p := profile(t, "gate:\n  inline: true\n")

	res := Check(input(p, "GET", "/cart"), key, nil)

	if res.Verdict != protocol.VerdictDeny || !res.Inline {
		t.Fatalf("verdict %s inline=%v, want deny inline", res.Verdict, res.Inline)
	}

	if res.Response != "auth_required" {
		t.Fatalf("response %q, want auth_required", res.Response)
	}

	if len(res.Cookies) != 1 || res.Cookies[0].Name != p.Src.Ticket.Cookie {
		t.Fatalf("ticket cookie missing: %+v", res.Cookies)
	}

	if !strings.HasPrefix(res.RedirectURL, "/waf/login?rd=") {
		t.Fatalf("fallback redirect %q", res.RedirectURL)
	}

	// Не навигация -- обычный 401, без формы и без билета.
	in := input(p, "POST", "/cart")

	if res := Check(in, key, nil); res.Inline || len(res.Cookies) != 0 {
		t.Fatalf("POST must not get the inline form: %+v", res)
	}
}

// Прежний рычаг читается как inline одно поколение.
func TestLegacyFormResponseMeansInline(t *testing.T) {
	p := profile(t, "gate:\n  form_response: auth_form\n")

	if !p.FormInline() {
		t.Fatal("form_response must map to inline")
	}
}

/*
 * Событие лестницы -- по нему обработчик выбирает правила профиля. Аноним
 * без куки, вошедший с целой сессией, вошедший не в ту дверь -- три разных
 * слова; вердикт при этом может быть любым, событие про клиента, а не про
 * исход.
 */
func TestEventOfTheLadder(t *testing.T) {
	p := profile(t, "")

	res := Check(input(p, "GET", "/cart"), key, nil)

	if res.Event != config.OnAnonymous {
		t.Fatalf("event %q, want anonymous (code %s)", res.Event, res.Code)
	}

	in := input(p, "GET", "/cart")
	in.Cookie = session(t, p.Src, nil)

	res = Check(in, key, nil)

	if res.Event != config.OnAuthenticated || res.Verdict != protocol.VerdictAllow {
		t.Fatalf("event %q verdict %q, want authenticated allow (code %s)",
			res.Event, res.Verdict, res.Code)
	}

	in.Cookie = "not-a-token"

	res = Check(in, key, nil)

	if res.Event != config.OnInvalid {
		t.Fatalf("event %q, want invalid (code %s)", res.Event, res.Code)
	}

	// Свой путь лестницу не проходит: события нет.
	res = Check(input(p, "GET", p.Src.Login.URI), key, nil)

	if res.Event != "" {
		t.Fatalf("event %q on the own path, want none", res.Event)
	}
}
