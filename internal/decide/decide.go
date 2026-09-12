/*
 * Лестница вердикта калитки. Чистая функция: ни шины, ни обменника, ни Redis --
 * всё, что нужно для решения, приходит аргументом. Поэтому её можно проверить
 * тестом на таблице, а не прогоном контура.
 *
 *   подпись сошлась, срок цел, привязка совпала, sid в списке → allow
 *   пора продлевать и это навигация                           → redirect /renew
 *   метод уводим и это навигация                              → redirect на форму
 *   иначе                                                     → deny 401
 *
 * Механизм один: кука и список. Подпись доказывает, что сессию выписали мы;
 * запись в активном списке -- что её не завершили. Удаление записи из списка
 * и есть завершение сессии, других каналов отзыва нет.
 *
 * Асимметрия GET и остального -- не украшение. Редирект на форму осмыслен там,
 * где ответ увидит человек; POST при 303 теряет тело, а fetch получает HTML
 * формы вместо ответа API. Поэтому им 401 с телом из каталога отказов.
 */

package decide

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/exemt/placitum-auth/internal/audit"
	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/jwt"
	"github.com/exemt/placitum-auth/internal/learn"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/token"
)

// Коды причины. Едут модулю, попадают в диагностический заголовок и выбирают
// запись каталога отказов.
const (
	CodeOK             = "AUTH_OK"
	CodeOff            = "AUTH_OFF"
	CodeSelf           = "AUTH_SELF"
	CodeObserve        = "AUTH_OBSERVE"
	CodeRenew          = "AUTH_RENEW"
	CodeReauth         = "AUTH_REAUTH"
	CodeSkipped        = "AUTH_SKIPPED"
	CodeNoSession      = "AUTH_NO_SESSION"
	CodeSessionBad     = "AUTH_SESSION_BAD"
	CodeSessionExpired = "AUTH_SESSION_EXPIRED"
	CodeSessionBind    = "AUTH_SESSION_BIND"
	CodeSessionScope   = "AUTH_SESSION_SCOPE"
	CodeSessionSource  = "AUTH_SESSION_SOURCE"
	CodeSessionRevoked = "AUTH_SESSION_REVOKED"
	// Список сессий объявлен, но зеркало без снапшота: решать нельзя ни в
	// какую сторону, и калитка закрыта. Отдельный код, чтобы в аудите отказ
	// шины не выглядел волной выходов.
	CodeListUnavailable = "AUTH_LIST_UNAVAILABLE"
	// Объект обменника лежал, а мы его не взяли: cookie не прочли, и о клиенте
	// это не говорит ничего.
	CodeStoreUnavailable = "AUTH_STORE_UNAVAILABLE"
	// Правило события пишет в набор подсеть или систему (write: net |
	// net_all | asn), а кодер гео молчит: записи не будет, и молча
	// пропускать её нельзя -- решает waf_exception маршрута.
	CodeGeoUnavailable = "AUTH_GEO_UNAVAILABLE"
	CodeForbidden      = "AUTH_FORBIDDEN"
	CodeUnknownProfile = "AUTH_UNKNOWN_PROFILE"
	CodeWrongPhase     = "AUTH_PHASE_NOT_SUPPORTED"
)

// Коды находок. Отдельные от кодов причины: причина едет модулю, находка --
// в аудит, и по ней строят разбор инцидента.
const (
	FindingNoSession      = "auth-no-session"
	FindingSessionBad     = "auth-session-bad"
	FindingSessionRevoked = "auth-session-revoked"
	FindingForbidden      = "auth-forbidden"
	FindingUnknownProfile = "auth-unknown-profile"
	FindingStore          = "auth-store-unavailable"
	FindingListDown       = "auth-list-unavailable"
)

/*
 * Sessions -- зеркало активного списка сессий. Список -- истина: запись в нём
 * означает, что сессию не завершили. ready=false -- списка не видно (зеркало
 * ещё без снапшота); это отказ списка, а не его пустота, и решалка обязана
 * закрыть калитку, а не открыть.
 */
type Sessions interface {
	Contains(subject, sid string) (ok, ready bool)
	// Lookup -- то же с самой записью: провайдеру app логин нужен из reason.
	Lookup(subject, sid string) (entry livelist.Entry, ok, ready bool)
}

type Input struct {
	Profile *config.Profile
	// Ask -- имя профиля, которое назвал маршрут. Нужно отдельно от Profile:
	// когда профиля нет, сказать об этом можно только по имени.
	Ask string

	Method   string
	URI      string
	Args     string
	ClientIP string

	Headers   []protocol.Header
	Cookie    string
	UserAgent string
	Accept    string

	// Prior -- высказывания предыдущих волн. Значат что-то только там, где в
	// профиле есть правило trigger.prior; без правила просьба соседа -- запись
	// в аудите, не больше.
	Prior []protocol.PriorVerdict

	// StoreUnavailable непустой означает, что заголовков не видно вовсе. Для
	// калитки это то же, что "cookie нет": решает лестница, а не отказ обменника.
	StoreUnavailable string

	Now time.Time
}

type Result struct {
	Verdict string
	Code    string
	Text    string

	Response       string
	RedirectURL    string
	RedirectStatus int

	/*
	 * Inline -- форма телом ответа: вердикт deny с билетом в Cookies, а
	 * страницу вызывающий берёт у auth-http и кладёт в обменник (лестница
	 * решает, но не ходит по сети). RedirectURL при этом заполнен запасным
	 * ходом: форма не досталась -- вызывающий отвечает редиректом.
	 */
	Inline bool

	Cookies []protocol.Cookie
	Headers map[string]string

	Session  *token.Session
	Findings []audit.Finding
	Engine   map[string]any

	// Sessions -- секция sessions реплая: чью сессию калитка увидела. Есть
	// только при открытой сессии, от вердикта не зависит.
	Sessions []protocol.Session

	// Event -- что лестница узнала о клиенте: authenticated, anonymous,
	// invalid, forbidden (config.On*). Пусто, когда узнавать было нечего --
	// профиль выключен, свой путь, сбой. По нему обработчик выбирает правила
	// профиля: просьбы соседям и записи в набор.
	Event string
}

/*
 * Check -- всё решение целиком. Key нужен для проверки подписи сессии и для
 * выписки билета формы; sessions -- зеркало активных списков. nil при
 * объявленном списке источника означает "списка не видно" и закрывает
 * калитку так же, как неготовое зеркало.
 */
func Check(in Input, key *token.Key, sessions Sessions) (res Result) {
	/*
	 * Профиля с таким именем нет: калитки на этом маршруте не существует.
	 * Прежний deny запирал вход за ошибку развёртывания, и решал это инспектор;
	 * теперь исход выбирает waf_exception класса inspector.
	 */
	if in.Profile == nil {
		return Result{
			Verdict: protocol.VerdictError,
			Code:    CodeUnknownProfile,
			Text:    in.Ask,
			Findings: []audit.Finding{{
				Code:     FindingUnknownProfile,
				Severity: audit.SeverityCritical,
				Target:   audit.TargetConn,
				Rule:     in.Ask,
			}},
		}
	}

	p := in.Profile

	engine := map[string]any{"profile": p.Name, "mode": p.Mode}

	// Наблюдение: ответ модулю заглушён на каждом запросе профиля, и флаг
	// стоит на каждой записи; would_* -- только там, где было что глушить.
	if p.Mode == config.ModeObserve {
		engine["passive"] = true
	}

	if in.StoreUnavailable != "" {
		engine["store"] = in.StoreUnavailable
	}

	if p.Mode == config.ModeOff {
		return allow(p, nil, CodeOff, engine)
	}

	/*
	 * Своя форма: страница, POST входа, renew и статика под login.uri. Вход
	 * на них -- рекурсия, поэтому allow до любой лестницы; так инспектор
	 * может стоять на локации формы, и локейшен без инспекторов ей больше
	 * не нужен.
	 */
	if p.OwnPath(in.URI) {
		engine["self"] = true

		return allow(p, nil, CodeSelf, engine)
	}

	/*
	 * Просьбы соседей разбираются один раз, и каждая получает исход -- он едет
	 * в аудит через engine: молчание в ответ на просьбу и есть тот случай,
	 * который потом разбирают.
	 */
	asked := priorAsk(in.Prior, p)

	if len(asked.outcomes) != 0 {
		engine["actions"] = asked.outcomes
	}

	sess, code, finding := open(in, p, key, sessions)

	/*
	 * Событие -- то, что лестница узнала о клиенте, на любом исходе ниже:
	 * вердикт может быть и allow под наблюдением, и редирект на форму, а
	 * «аноним» остаётся анонимом. Ставится на выходе, чтобы не размазывать по
	 * каждому return.
	 */
	defer func() {
		res.Event = eventOf(sess, code, res)
	}()

	/*
	 * Список сессий -- истина, а зеркала нет: жив ли этот вход, сказать нечем.
	 * Прежний отказ уводил на форму каждого вошедшего -- отказ обслуживания
	 * из-за отставшего зеркала, и решал его инспектор. Теперь это признанное
	 * отсутствие проверки, а исход выбирает waf_exception класса inspector.
	 */
	if code == CodeListUnavailable {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     code,
			Findings: finding,
			Engine:   engine,
		}
	}

	if sess != nil && !p.Allows(sess.Groups) {
		/*
		 * Вошёл, но не в ту дверь: сессия цела, а группы допуска у профиля
		 * нет. Отсюда только отказ -- на форму такого не уводят ни при каком
		 * методе. Он там уже был, и второй вход выдаст ту же сессию с теми же
		 * группами: получилась бы карусель, в которой человеку нечего сделать.
		 *
		 * Своя запись каталога (403) и свой код: 401 «войдите» вошедшему
		 * врёт, а по AUTH_FORBIDDEN в X-WAF-Debug видно, что калитка сработала
		 * именно допуском, а не сроком или подписью.
		 */
		engine["forbidden"] = strings.Join(p.Gate.Groups, ",")

		if p.Mode == config.ModeObserve {
			engine["would_verdict"] = protocol.VerdictDeny
			engine["would_code"] = CodeForbidden

			res := allow(p, sess, CodeObserve, engine)
			res.Findings = forbidden(sess, p)

			return res
		}

		return Result{
			Verdict:  protocol.VerdictDeny,
			Code:     CodeForbidden,
			Response: p.Gate.ForbiddenResponse,
			Findings: forbidden(sess, p),
			Engine:   engine,
		}
	}

	if sess != nil {
		/*
		 * Сессия цела, но сосед просит повторную аутентификацию. Просьба
		 * пропустить сильнее: она действует только по правилу с именем
		 * отправителя, то есть это решение оператора, а не соседа.
		 *
		 * Reauth -- это вход заново, а не продление: клиент уходит на форму с
		 * билетом, как будто сессии нет. Свежую сессию не трогаем -- иначе
		 * только что вошедший ездил бы на форму по кругу.
		 */
		if asked.reauth && !asked.skip && reauthDue(in, p, sess) {
			engine["reauth"] = true

			if p.Mode == config.ModeObserve {
				engine["would_verdict"] = wouldBe(in, p)
				engine["would_code"] = CodeReauth

				res := allow(p, sess, CodeObserve, engine)
				res.Findings = finding

				return res
			}

			if navigational(in, p) {
				res := gate(in, p, key, CodeReauth, engine)
				res.Findings = finding

				return res
			}

			return Result{
				Verdict:  protocol.VerdictDeny,
				Code:     CodeReauth,
				Response: p.Gate.DenyResponse,
				Findings: finding,
				Engine:   engine,
			}
		}

		if sess.NeedsRenew(in.Now) && navigational(in, p) {
			/*
			 * Продление -- тоже редирект, и наблюдение его глушит наравне с
			 * остальными: клиент проходит с сессией как есть, а в аудите
			 * видно, что enforce увёл бы его на /renew.
			 */
			if p.Mode == config.ModeObserve {
				engine["renew"] = true
				engine["would_verdict"] = protocol.VerdictRedirect
				engine["would_code"] = CodeRenew

				return allow(p, sess, CodeObserve, engine)
			}

			return renew(in, p, engine)
		}

		return allow(p, sess, CodeOK, engine)
	}

	/*
	 * Просьба пропустить гасит требование входа целиком. Заголовки личности
	 * всё равно перезаписываются пустыми: клиент едет внутрь без имени, а не
	 * под тем, которое выбрал себе сам.
	 */
	if asked.skip {
		res := allow(p, nil, CodeSkipped, engine)
		res.Findings = finding

		return res
	}

	/*
	 * Наблюдение отвечает модулю allow всегда и говорит в аудите, что решило
	 * бы в enforce. Это единственный способ выкатить калитку на живой маршрут,
	 * не заперев за ней пользователей: без него первый же профиль с опечаткой
	 * в login.uri стоил бы всего трафика. Всё остальное -- сессии, просьбы
	 * соседей, заголовки личности -- работает как в enforce.
	 */
	if p.Mode == config.ModeObserve {
		engine["would_verdict"] = wouldBe(in, p)
		engine["would_code"] = code

		res := allow(p, nil, CodeObserve, engine)
		res.Findings = finding

		return res
	}

	if navigational(in, p) {
		res := gate(in, p, key, code, engine)
		res.Findings = finding

		return res
	}

	return Result{
		Verdict:  protocol.VerdictDeny,
		Code:     code,
		Response: p.Gate.DenyResponse,
		Findings: finding,
		Engine:   engine,
	}
}

/*
 * gate -- навигационный запрос без права прохода: на форму. Редирект с
 * билетом либо, в режиме inline, тот же билет и deny: страницу вызывающий
 * положит в обменник и назовёт секцией rewrite, а RedirectURL остаётся запасным
 * ходом на случай, когда форма не досталась. Абсолютного адреса в контуре
 * при inline не остаётся вовсе.
 */
func gate(in Input, p *config.Profile, key *token.Key, code string,
	engine map[string]any) Result {

	res := redirect(in, p, key, code, engine)

	if p.FormInline() && res.Verdict == protocol.VerdictRedirect {
		res.Verdict = protocol.VerdictDeny
		res.Response = p.Gate.DenyResponse
		res.Inline = true
		engine["inline"] = true
	}

	return res
}

/*
 * open проверяет cookie и возвращает сессию либо код, по которому её нет.
 * Различие кодов -- для оператора: клиенту все они означают одно и то же, а в
 * аудите "подпись не сошлась" и "срок вышел" -- совсем разные события.
 */
func open(in Input, p *config.Profile, key *token.Key, sessions Sessions) (
	*token.Session, string, []audit.Finding) {

	/*
	 * Внешние провайдеры: сессию выписал не контур, и открывается она не
	 * ключом, а схемой claims либо списком доверенных. Своей лестнице --
	 * подпись, привязка, штамп источника -- там проверять нечего.
	 */
	switch p.Src.Provider {
	case config.ProviderJWT:
		return openJWT(in, p.Src)

	case config.ProviderApp:
		return openApp(in, p.Src, sessions)
	}

	if in.Cookie == "" {
		return nil, CodeNoSession, absent(in)
	}

	src := p.Src

	want := token.Bind{}

	if src.BindsNet() {
		want.Net = token.Subnet(in.ClientIP, src.Session.Subnet.V4, src.Session.Subnet.V6)
	}

	if src.BindsUA() {
		want.UA = token.Fingerprint(in.UserAgent)
	}

	sess, err := key.OpenSession(in.Cookie, in.Now, want)

	switch {
	case errors.Is(err, token.ErrExpired):
		return nil, CodeSessionExpired, nil

	case errors.Is(err, token.ErrBind):
		return nil, CodeSessionBind, bad(FindingSessionBad, "bind")

	case err != nil:
		/*
		 * Не сошлась подпись -- это либо чужой ключ, либо подделка. Второе
		 * стоит увидеть в аудите: одиночная битая cookie -- шум, поток таких
		 * с одного адреса -- подбор.
		 */
		return nil, CodeSessionBad, bad(FindingSessionBad, "signature")
	}

	/*
	 * Область действия -- имя cookie, под которую токен выписан. Кука
	 * принадлежит источнику, и токен, выписанный под другое имя, сюда попасть
	 * может только переклеенным.
	 */
	if sess.Scope != "" && sess.Scope != src.Session.Cookie {
		return nil, CodeSessionScope, nil
	}

	/*
	 * Штамп источника. Профили одного источника принимают сессии друг друга;
	 * чужой источник -- чужой каталог пользователей, и его сессия здесь не
	 * значит ничего, каким бы именем ни называлась кука. Это и есть граница
	 * независимости: пространство сессий определяет ссылка source, а не
	 * совпадение строк в двух конфигах.
	 */
	if sess.Iss != src.Name {
		return nil, CodeSessionSource, nil
	}

	/*
	 * Список -- истина. Свежая сессия проходит по одной подписи: запись едет
	 * через секвенсор контроллера и возвращается снапшотом, и первые секунды
	 * после входа сессия законно живёт быстрее своей записи. Дальше -- только
	 * по списку: нет записи, значит сессию завершили.
	 */
	if src.List.Enabled() && in.Now.Sub(time.Unix(sess.Issued, 0)) > src.List.Grace.D() {
		if sessions == nil {
			return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
		}

		listed, ready := sessions.Contains(src.List.Sessions, sess.SID)

		if !ready {
			return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
		}

		if !listed {
			return nil, CodeSessionRevoked, bad(FindingSessionRevoked, sess.SID)
		}
	}

	return sess, CodeOK, nil
}

// absent -- находка к «сессии нет»: заголовков не видно вовсе -- это отказ
// обменника, и в аудите он обязан отличаться от клиента без куки.
func absent(in Input) []audit.Finding {
	if in.StoreUnavailable == "" {
		return nil
	}

	return []audit.Finding{{
		Code:     FindingStore,
		Severity: audit.SeverityHigh,
		Target:   audit.TargetConn,
		Rule:     in.StoreUnavailable,
	}}
}

/*
 * openJWT -- сессия из чужого токена. Алгоритм называет источник, а не
 * заголовок токена; без ключа (alg none) разбор без проверки, и запись в
 * аудите едет с verified: false. Сроки -- по claims источника с допуском
 * leeway; издатель и аудитория -- если названы.
 */
func openJWT(in Input, src *config.Source) (*token.Session, string, []audit.Finding) {
	j := src.Providers.JWT

	raw := in.Cookie

	if j.Header != "" {
		raw = bearer(headerValue(in.Headers, j.Header), j.Prefix)
	}

	if raw == "" {
		return nil, CodeNoSession, absent(in)
	}

	tok, err := jwt.Parse(raw)
	if err != nil {
		return nil, CodeSessionBad, bad(FindingSessionBad, "malformed")
	}

	if j.Verify.Alg != config.JWTAlgNone {
		if err := tok.Verify(j.Verify.Alg, j.Key); err != nil {
			// Как у своего токена: одиночный битый -- шум, поток -- подбор.
			return nil, CodeSessionBad, bad(FindingSessionBad, "signature")
		}
	}

	leeway := int64(j.Verify.Leeway.D().Seconds())
	now := in.Now.Unix()

	expiry, hasExpiry := tok.Int(j.Claims.Expiry)
	if hasExpiry && now > expiry+leeway {
		return nil, CodeSessionExpired, nil
	}

	if nbf, ok := tok.Int("nbf"); ok && now < nbf-leeway {
		return nil, CodeSessionBad, bad(FindingSessionBad, "nbf")
	}

	if j.Verify.Issuer != "" && tok.String("iss") != j.Verify.Issuer {
		return nil, CodeSessionSource, bad(FindingSessionBad, "issuer")
	}

	if j.Verify.Audience != "" && !contains(tok.Strings("aud"), j.Verify.Audience) {
		return nil, CodeSessionScope, bad(FindingSessionBad, "audience")
	}

	/*
	 * Идентификатор: claim источника, затем jti, затем отпечаток токена --
	 * запись в аудите обязана различать сессии одного пользователя, а
	 * сырой токен туда не кладут.
	 */
	id := tok.String(j.Claims.Session)

	if id == "" {
		id = tok.String("jti")
	}

	if id == "" {
		id = tok.Hash()
	}

	issued, _ := tok.Int(j.Claims.Issued)

	return &token.Session{
		SID:    id,
		Sub:    tok.String(j.Claims.User),
		Issued: issued,
		Expiry: expiry,
		Iss:    src.Name,
		AMR:    []string{"jwt"},
		Groups: tok.Strings(j.Claims.Groups),
	}, CodeOK, nil
}

/*
 * openApp -- кука приложения, доверенная через список. Кука есть, а записи
 * нет -- это «сессии нет», а не «сессия плохая»: приложение могло выдать её
 * до того, как калитка встала на маршрут входа, и человеку остаётся войти
 * заново. Списка не видно -- калитка закрыта, как у своих сессий.
 */
func openApp(in Input, src *config.Source, sessions Sessions) (
	*token.Session, string, []audit.Finding) {

	if in.Cookie == "" {
		return nil, CodeNoSession, absent(in)
	}

	id := learn.Hash(in.Cookie)

	if sessions == nil {
		return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
	}

	entry, listed, ready := sessions.Lookup(src.List.Sessions, id)

	if !ready {
		return nil, CodeListUnavailable, bad(FindingListDown, src.List.Sessions)
	}

	if !listed {
		return nil, CodeNoSession, nil
	}

	return &token.Session{
		SID:    id,
		Sub:    learn.UserOf(entry.Reason),
		Expiry: entry.Expires / 1000,
		Iss:    src.Name,
		AMR:    []string{"app"},
	}, CodeOK, nil
}

func headerValue(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if strings.EqualFold(h.Name(), name) {
			return h.Value()
		}
	}

	return ""
}

// bearer снимает префикс схемы («Bearer ») без учёта регистра. Пустой
// префикс -- значение как есть.
func bearer(value, prefix string) string {
	value = strings.TrimSpace(value)

	if prefix == "" {
		return value
	}

	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}

	return strings.TrimSpace(value[len(prefix):])
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}

	return false
}

/*
 * ask -- что соседи попросили и что из этого прошло через правила профиля.
 * Нулевая структура означает "никто ничего не просил либо ни одно правило не
 * подошло", и это самый частый исход.
 */
type ask struct {
	reauth bool // потребовать повторную аутентификацию
	skip   bool // не проверять этот запрос вовсе

	// outcomes -- по строке на каждую доставленную просьбу, для kind=inspector.
	outcomes []ActionOutcome
}

// Исход одной просьбы. "Нет правила" -- полноправный исход, а не пропуск.
const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

/*
 * ActionOutcome -- что сосед просил и что из этого вышло у нас. Без исхода
 * запись бесполезна: видно, что просьба была, и не видно, почему ничего не
 * случилось.
 *
 * Три исхода "не доставлено" сюда попасть не могут по построению -- пассивный
 * отправитель, переполнение waf_actions_max и урезание по маршруту отсекаются
 * до нас, и живут они в записи модуля kind=request.
 */
type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Value int    `json:"value,omitempty"`
	Delta int    `json:"delta,omitempty"`

	Outcome string `json:"outcome"`
}

func priorAsk(prior []protocol.PriorVerdict, p *config.Profile) ask {
	var a ask

	for _, v := range prior {
		if v.Phase != "" && v.Phase != protocol.PhaseRequest {
			continue
		}

		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, p)
		}
	}

	return a
}

/*
 * deliver -- одна просьба против всех правил профиля. Цикл по действиям
 * снаружи, а не по правилам: исход у просьбы один, сколько бы правил её ни
 * зацепило.
 */
func (a *ask) deliver(from string, act protocol.Action, p *config.Profile) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Value:   act.Value,
		Delta:   act.Delta,
		Outcome: OutcomeNoRule,
	}

	for _, r := range p.Trigger.Prior {
		if r.From != config.AnyInspector && r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		switch act.Do {
		case protocol.DoReauth:
			a.reauth = true

		case protocol.DoSkip:
			a.skip = true
		}

		out.Outcome = OutcomeApplied
	}

	a.outcomes = append(a.outcomes, out)
}

/*
 * eventOf -- событие для правил профиля по итогу лестницы. Чужая группа
 * сильнее «вошёл»: сессия цела, но допуска нет, и соседям про такого стоит
 * знать именно это. Сбой списка событием не считается: о клиенте ничего не
 * узнали.
 */
func eventOf(sess *token.Session, code string, res Result) string {
	if _, forbidden := res.Engine["forbidden"]; forbidden {
		return config.OnForbidden
	}

	if sess != nil {
		return config.OnAuthenticated
	}

	switch code {
	case CodeNoSession:
		return config.OnAnonymous

	case CodeListUnavailable, "":
		return ""
	}

	return config.OnInvalid
}

/*
 * reauthDue -- действует ли просьба на эту сессию. Сессия моложе reauth_after
 * не трогается: клиент только что доказал, кто он, а отправитель шлёт просьбу
 * на каждом запросе и не знает, что вход уже случился, -- без этой отсечки
 * форма превращается в карусель.
 */
func reauthDue(in Input, p *config.Profile, sess *token.Session) bool {
	after := p.Trigger.ReauthAfter.D()
	if after == 0 {
		return true
	}

	return in.Now.Unix() >= sess.Issued+int64(after.Seconds())
}

/*
 * forbidden -- находка о попытке зайти не в свою зону. Она интереснее
 * остального, что пишет калитка: битая cookie -- шум, а вошедший, который
 * ломится на чужой маршрут, -- либо ошибка выдачи прав, либо разведка. В
 * правило кладём субъекта: по нему разбор инцидента находит человека.
 */
func forbidden(sess *token.Session, p *config.Profile) []audit.Finding {
	return []audit.Finding{{
		Code:     FindingForbidden,
		Severity: audit.SeverityHigh,
		Target:   audit.TargetConn,
		Rule:     sess.Sub + " not in " + strings.Join(p.Gate.Groups, ","),
	}}
}

func bad(code, rule string) []audit.Finding {
	return []audit.Finding{{
		Code:     code,
		Severity: audit.SeverityMedium,
		Target:   audit.TargetConn,
		Rule:     rule,
	}}
}

/*
 * allow ставит заголовки личности -- единственное переопределение, которое
 * модуль применяет на этом вердикте.
 *
 * Ставятся они всегда и все, включая пустые: headers.unset на фазе запроса
 * модуль не поддерживает, и подделанный клиентом X-WAF-User снимается только
 * перезаписью. Пропустить пустое значение значило бы пустить клиента внутрь
 * под тем именем, которое он себе выбрал сам.
 */
func allow(p *config.Profile, s *token.Session, code string, engine map[string]any) Result {
	res := Result{
		Verdict: protocol.VerdictAllow,
		Code:    code,
		Headers: map[string]string{},
		Session: s,
		Engine:  engine,
	}

	user, groups, method := "", "", ""

	if s != nil {
		user = s.Sub
		groups = strings.Join(s.Groups, ",")
		method = strings.Join(s.AMR, "+")

		engine["sub"] = s.Sub
		engine["sid"] = s.SID
	}

	// Имена заголовков живут на источнике; профиль mode: off может жить без
	// него -- тогда и переопределять нечего.
	if p.Src != nil {
		setHeader(res.Headers, p.Src.Upstream.User, user)
		setHeader(res.Headers, p.Src.Upstream.Groups, groups)
		setHeader(res.Headers, p.Src.Upstream.Method, method)
	}

	res.Sessions = sessionsOf(p.Src, s)

	return res
}

/*
 * sessionsOf -- запись секции sessions по открытой сессии. Вид -- по
 * провайдеру источника; verified у jwt -- была ли подпись: без ключа (alg
 * none) claims написал клиент, и запись обязана это сказать.
 */
func sessionsOf(src *config.Source, s *token.Session) []protocol.Session {
	if src == nil || s == nil {
		return nil
	}

	entry := protocol.Session{
		Source:   src.Name,
		Kind:     protocol.SessionOwn,
		User:     s.Sub,
		ID:       s.SID,
		Verified: true,
		Issued:   s.Issued,
		Expires:  s.Expiry,
		Groups:   s.Groups,
	}

	switch src.Provider {
	case config.ProviderJWT:
		entry.Kind = protocol.SessionJWT
		entry.Verified = src.Providers.JWT != nil &&
			src.Providers.JWT.Verify.Alg != config.JWTAlgNone

	case config.ProviderApp:
		entry.Kind = protocol.SessionApp
	}

	return []protocol.Session{entry}
}

func setHeader(dst map[string]string, name, value string) {
	if name == "" {
		return
	}

	dst[name] = value
}

/*
 * redirect уводит на форму и кладёт билет: одноразовый nonce и адрес возврата.
 *
 * Nonce здесь только подписывается, в Redis не пишется. Гасит его форма при
 * первом принятом POST -- так на горячем пути инспектора нет ни одной записи в
 * хранилище, а одноразовость всё равно обеспечена.
 */
func redirect(in Input, p *config.Profile, key *token.Key, code string,
	engine map[string]any) Result {

	/*
	 * Внешний провайдер: страница входа -- приложения, билет ей ни к чему, а
	 * ?rd= она не поймёт. Адреса нет -- 401, как ненавигационному.
	 */
	if p.Src.External() {
		if p.Src.Login.URI == "" {
			return Result{
				Verdict:  protocol.VerdictDeny,
				Code:     code,
				Response: p.Gate.DenyResponse,
				Engine:   engine,
			}
		}

		return Result{
			Verdict:        protocol.VerdictRedirect,
			Code:           code,
			RedirectURL:    p.Src.Login.URI,
			RedirectStatus: p.Gate.RedirectStatus,
			Engine:         engine,
		}
	}

	back := returnPath(in.URI, in.Args)

	// Билет скоупится на источник: форма принадлежит ему, и профили одного
	// источника делят один билет, как делят одну форму.
	ticket := &token.Ticket{
		Nonce:  token.NewID(),
		Return: back,
		Scope:  p.Src.Name,
		Expiry: in.Now.Add(p.Src.Ticket.TTL.D()).Unix(),
	}

	sealed, err := key.SealTicket(ticket)
	if err != nil {
		// Подписать нечем -- значит формы не будет. Отказ честнее редиректа,
		// который приведёт на страницу без билета и без возврата.
		return Result{
			Verdict:  protocol.VerdictDeny,
			Code:     code,
			Response: p.Gate.DenyResponse,
			Engine:   engine,
		}
	}

	target := p.Src.Login.URI
	if back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	return Result{
		Verdict:        protocol.VerdictRedirect,
		Code:           code,
		RedirectURL:    target,
		RedirectStatus: p.Gate.RedirectStatus,
		Cookies: []protocol.Cookie{{
			Name:   p.Src.Ticket.Cookie,
			Value:  sealed,
			Path:   p.Src.Login.URI,
			MaxAge: int(p.Src.Ticket.TTL.D().Seconds()),
		}},
		Engine: engine,
	}
}

// renew -- перевыпуск действующей сессии. Пароль не спрашивают: продление это
// не вход. Cookie здесь не ставится -- её выпишет форма, проверив старый токен.
func renew(in Input, p *config.Profile, engine map[string]any) Result {
	back := returnPath(in.URI, in.Args)

	target := strings.TrimRight(p.Src.Login.URI, "/") + "/renew"
	if back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	engine["renew"] = true

	return Result{
		Verdict:        protocol.VerdictRedirect,
		Code:           CodeRenew,
		RedirectURL:    target,
		RedirectStatus: p.Gate.RedirectStatus,
		Engine:         engine,
	}
}

/*
 * navigational -- увидит ли ответ человек в браузере.
 *
 * Метод из списка -- обязательное условие: остальные при 303 теряют тело.
 * Уточнение нужно из-за фронтенда: GET без text/html в Accept -- это XHR,
 * которому HTML формы не поможет. Маршруты API, где 401 нужен всегда, --
 * профиль-спутник с пустыми redirect_methods, а не список путей здесь.
 */
func navigational(in Input, p *config.Profile) bool {
	if !p.RedirectsMethod(in.Method) {
		return false
	}

	if p.Gate.HTMLOnly && !acceptsHTML(in.Accept) {
		return false
	}

	return true
}

func acceptsHTML(accept string) bool {
	if accept == "" {
		return false
	}

	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml") ||
		strings.Contains(accept, "*/*")
}

func wouldBe(in Input, p *config.Profile) string {
	if navigational(in, p) {
		return protocol.VerdictRedirect
	}

	return protocol.VerdictDeny
}

/*
 * returnPath собирает адрес возврата и обязан быть параноидальным: значение
 * уезжает в query редиректа, а оттуда -- в Location формы. Всё, что не похоже
 * на локальный путь, отбрасывается целиком: пустой rd означает возврат на
 * корень, и это лучше открытого редиректа.
 */
func returnPath(uri, args string) string {
	const max = 1024

	if uri == "" || uri[0] != '/' {
		return ""
	}

	// "//host/path" браузер читает как абсолютный адрес без схемы, а наивная
	// проверка пути -- как локальный.
	if strings.HasPrefix(uri, "//") {
		return ""
	}

	out := uri
	if args != "" {
		out += "?" + args
	}

	if len(out) > max {
		return ""
	}

	for i := 0; i < len(out); i++ {
		c := out[i]
		if c < 0x21 || c > 0x7e || c == '\\' {
			return ""
		}
	}

	return out
}
