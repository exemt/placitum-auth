/*
 * Профиль калитки: политика допуска одного маршрута.
 *
 * Профиль выбирается тегом profile= записи waf_inspector и приезжает в
 * route.profile -- тем же механизмом, что у ip и modsec. Всё про сам вход --
 * провайдер, форма, сессии -- живёт в источнике (source.go); профиль называет
 * его ключом source: и добавляет только то, что различается между маршрутами:
 * режим, условия допуска и правила приёма чужих просьб.
 *
 * Профили одного источника принимают сессии друг друга; профили разных
 * источников независимы -- сессия несёт имя источника, и чужая не открывает
 * ничего. Один процесс обслуживает сколько угодно источников и профилей.
 *
 * Всё, что здесь проверяется, проверяется при загрузке. Профиль с опечаткой
 * обязан не подняться, а не пропустить трафик мимо калитки на первом запросе.
 */

package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-auth/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	// AnyInspector в правиле prior -- сигнал принимается от любого соседа.
	AnyInspector = "*"
)

// DefaultName -- профиль, который применяется, когда маршрут не назвал
// никакого. Отсутствие такого профиля -- ошибка старта: молча пускать трафик
// мимо калитки нельзя.
const DefaultName = "default"

/*
 * Duration -- срок в человеческой записи ("8h", "30s"). Отдельный тип, потому
 * что yaml.v3 не знает time.Duration, а число секунд в конфиге, который правят
 * руками, читается хуже, чем ошибается.
 */
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		*d = 0
		return nil
	}

	v, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}

	if v < 0 {
		return fmt.Errorf("duration must not be negative: %q", raw)
	}

	*d = Duration(v)

	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Profile struct {
	// Имя -- имя каталога, а не поле файла: два источника истины для одного
	// имени разъезжаются при первом переименовании.
	Name string `yaml:"-"`

	Mode string `yaml:"mode"`

	/*
	 * Source -- имя источника входа. Обязателен всюду, кроме mode: off:
	 * наблюдающий профиль открывает сессии, а спутник без формы проверяет куку
	 * -- и то и другое берётся из источника.
	 */
	Source string `yaml:"source"`

	Gate    Gate    `yaml:"gate"`
	Trigger Trigger `yaml:"trigger"`

	/*
	 * Rules -- правила по событиям волны: «когда → что сделать». Калитка знает
	 * о клиенте то, чего не знает никто -- вошёл ли он и кто он, -- и здесь
	 * говорит об этом соседям: вошедшему не показывать капчу, аноним на
	 * закрытой зоне -- в корзину счётчика, чужая группа -- метка в журнале.
	 */
	Rules []EventRule `yaml:"rules"`

	// Src -- разрешённая ссылка на источник. Заполняет загрузчик снапшота;
	// nil только у mode: off без source.
	Src *Source `yaml:"-"`
}

/*
 * События правил. Все четыре случаются на волне инспектора, поэтому им
 * доступны просьбы; но просьба соседу доедет только с allow -- отказ и
 * редирект обрывают фазу. Поэтому у anonymous, invalid и forbidden загрузчик
 * пускает только глаголы записи маршрута: журнал, архив, метку, очки.
 */
const (
	// OnAuthenticated -- сессия цела и допуск есть: клиент вошёл.
	OnAuthenticated = "authenticated"
	// OnAnonymous -- куки нет вовсе: клиент никогда здесь не входил.
	OnAnonymous = "anonymous"
	// OnInvalid -- кука была, но не годится: истекла, отозвана, чужая
	// сеть или чужой источник.
	OnInvalid = "invalid"
	// OnForbidden -- вошёл, но не в ту дверь: группы допуска нет.
	OnForbidden = "forbidden"
)

// askTravels -- на этом событии просьба соседу доедет: фаза не оборвана.
func askTravels(on string) bool {
	return on == OnAuthenticated
}

// Повод: то же ограничение, которым модуль отбраковывает действие с провода.
var eventCodeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Имя корзины у note и группы у mutate: алфавит имён получателя.
var eventNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

/*
 * EventRule -- правило по событию: та же форма, что строки профиля адреса и
 * правила капчи -- «когда → что сделать». Действие ровно одно: просьба
 * соседу либо запись адреса клиента в набор.
 */
type EventRule struct {
	On string `yaml:"on"`

	// Просьба соседу -- форма канала действий.
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Phase -- фаза вызова адресата у управляющих глаголов; пусто -- всем
	// вызовам имени.
	Phase string `yaml:"phase"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Counter -- имя корзины получателя при do: note: селектор поверх его
	// правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `yaml:"counter"`
	// Group и Set -- только при do: mutate, оба обязательны; у глаголов
	// записи Set -- писать или нет.
	Group string `yaml:"group"`
	Set   string `yaml:"set"`
	// Marker -- только у mark, и там обязателен: метка события на записи.
	Marker string `yaml:"marker"`
	// Объекты просьбы записи (audit / archive); срок архива -- тот же ttl,
	// что у записи в набор: у строки либо просьба, либо запись.
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	// Запись в живой набор: имя набора, кого писать (Write) и срок.
	List string `yaml:"list"`
	// Write -- адрес клиента (addr, по умолчанию) либо то, во что он
	// разворачивается у кодера гео: net, net_all, asn (WriteNet и соседи).
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	Code string `yaml:"code"`
}

/*
 * Кого писать в набор -- те же слова, что у остальных отправителей: адрес
 * клиента; эффективный анонс, самый узкий (net); все анонсы, накрывающие
 * адрес, включая чужие широкие (net_all); систему целиком, все её анонсы
 * (asn). Подсеть и систему разворачивает обработчик у кодера гео.
 */
const (
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

func validateEventRule(i int, r EventRule) error {
	at := fmt.Sprintf("rules[%d]", i)

	switch r.On {
	case OnAuthenticated, OnAnonymous, OnInvalid, OnForbidden:
	default:
		return fmt.Errorf("%s: on must be authenticated, anonymous, invalid or "+
			"forbidden, got %q", at, r.On)
	}

	if (r.Do == "") == (r.List == "") {
		return fmt.Errorf("%s: exactly one of do or list", at)
	}

	if r.Do != "" {
		// Кого писать -- слово записи в набор; у просьбы ему нечего значить.
		if r.Write != "" {
			return fmt.Errorf("%s: write is only for a list write", at)
		}

		if err := validateAsk(at, r); err != nil {
			return err
		}
	} else {
		if r.TTL == 0 {
			return fmt.Errorf("%s: ttl is required for a list write", at)
		}

		if !eventNameRe.MatchString(r.List) {
			return fmt.Errorf("%s: bad list name %q", at, r.List)
		}

		switch r.Write {
		case "", WriteAddr, WriteNet, WriteNetAll, WriteASN:
		default:
			return fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
				at, WriteAddr, WriteNet, WriteNetAll, WriteASN, r.Write)
		}
	}

	if r.Code != "" && !eventCodeRe.MatchString(r.Code) {
		return fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, r.Code)
	}

	return nil
}

/*
 * validateAsk -- просьба соседу: та же отбраковка, что у модуля на проводе, и
 * тот же словарь, что у остальных отправителей. Калитка стоит только на фазе
 * запроса: осей conn и response у неё не бывает.
 */
func validateAsk(at string, r EventRule) error {
	var axes []string

	switch r.Do {
	case protocol.DoChallenge, protocol.DoThreshold, protocol.DoSkip,
		protocol.DoMutate:
		axes = []string{protocol.ApplyRequest}

	case protocol.DoReauth:
		axes = []string{protocol.ApplySession}

	case protocol.DoNote:
		axes = []string{
			protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession,
		}

	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff,
		protocol.DoAudit, protocol.DoArchive, protocol.DoMark, protocol.DoScore:
		axes = []string{protocol.ApplyRequest}

	default:
		return fmt.Errorf("%s: unknown do %q", at, r.Do)
	}

	// Отказ и редирект обрывают фазу: просьбе соседу с них не уехать, и
	// правило, собранное мышью, молча ничего бы не делало. Глаголы записи
	// исполняет модуль, а отказ -- главный случай, когда запрос стоит сохранить.
	if !askTravels(r.On) && !recordVerb(r.Do) {
		return fmt.Errorf("%s: %s ends the phase with a redirect or deny, "+
			"an ask has nowhere to go: only audit, archive, mark and score", at, r.On)
	}

	apply := r.Apply

	if apply == "" && len(axes) == 1 {
		apply = axes[0]
	}

	ok := false

	for _, a := range axes {
		if a == apply {
			ok = true
		}
	}

	if !ok {
		return fmt.Errorf("%s: apply %q is not allowed for %q", at, r.Apply, r.Do)
	}

	if controlVerb(r.Do) && r.To == "" {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", at, r.Do)
	}

	if err := checkPhaseAsk(r.Do, r.Phase, r.Axis()); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}

	if recordVerb(r.Do) && r.To != "" {
		return fmt.Errorf("%s: %s takes no to: the module serves the route's own record", at, r.Do)
	}

	if r.Do == protocol.DoThreshold {
		if r.Delta == nil || *r.Delta == 0 {
			return fmt.Errorf("%s: threshold needs a non-zero delta", at)
		}

		if *r.Delta < -100 || *r.Delta > 900 {
			return fmt.Errorf("%s: delta %d is out of -100..900 percent", at, *r.Delta)
		}
	} else if r.Delta != nil {
		return fmt.Errorf("%s: delta is only for threshold", at)
	}

	switch r.Do {
	case protocol.DoNote:
		if r.Value == nil || *r.Value == 0 {
			return fmt.Errorf("%s: note needs a non-zero value", at)
		}

		if *r.Value < -100 || *r.Value > 100 {
			return fmt.Errorf("%s: value %d is out of -100..100 percent", at, *r.Value)
		}

		if r.Counter != "" && !eventNameRe.MatchString(r.Counter) {
			return fmt.Errorf("%s: bad counter name %q", at, r.Counter)
		}

	case protocol.DoScore:
		if r.Value == nil || *r.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", at)
		}

		if *r.Value < -100 || *r.Value > 100 {
			return fmt.Errorf("%s: value %d is out of -100..100", at, *r.Value)
		}

		if r.Counter != "" {
			return fmt.Errorf("%s: counter is only for note", at)
		}

	default:
		if r.Value != nil {
			return fmt.Errorf("%s: value is only for note and score", at)
		}

		if r.Counter != "" {
			return fmt.Errorf("%s: counter is only for note", at)
		}
	}

	if r.Do == protocol.DoMutate {
		if r.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", at)
		}

		if !eventNameRe.MatchString(r.Group) {
			return fmt.Errorf("%s: bad group name %q", at, r.Group)
		}

		if r.Set != "on" && r.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", at, r.Set)
		}
	} else if r.Group != "" || (r.Set != "" && !auditVerb(r.Do)) {
		return fmt.Errorf("%s: group and set are only for mutate, audit and archive", at)
	}

	if r.Do == protocol.DoMark {
		if err := protocol.CheckMarker(r.Marker); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
	} else if r.Marker != "" {
		return fmt.Errorf("%s: marker is only for mark", at)
	}

	if auditVerb(r.Do) {
		if r.Set != "on" && r.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", at, r.Do, r.Set)
		}

		if r.Set == "off" && (r.TTL != 0 || len(r.When) != 0 ||
			r.Headers != nil || r.Args != nil || r.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", at)
		}

		if r.Do == protocol.DoAudit && (r.TTL != 0 || len(r.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", at)
		}

		if _, err := protocol.CheckArchiveWhen(r.When); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", r.Headers}, {"args", r.Args}, {"body", r.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
		}
	} else {
		if len(r.When) != 0 || r.Headers != nil || r.Args != nil || r.Body != nil {
			return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", at)
		}

		if r.TTL != 0 {
			return fmt.Errorf("%s: ttl is only for a list write or do: archive", at)
		}
	}

	return nil
}

// auditVerb -- глагол записи: журнал либо архив маршрута.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

// recordVerb -- адресат глагола не сосед, а запись самого маршрута.
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// controlVerb -- режим вызова соседа: исполняет модуль, адресат обязателен.
func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

// Axis -- ось просьбы с досочинённой единственной: то, что уедет на провод.
func (r EventRule) Axis() string {
	if r.Apply != "" {
		return r.Apply
	}

	switch r.Do {
	case protocol.DoReauth:
		return protocol.ApplySession

	case protocol.DoNote:
		return ""
	}

	return protocol.ApplyRequest
}

// RulesFor -- правила события в порядке оператора.
func (p *Profile) RulesFor(on string) []EventRule {
	var out []EventRule

	for _, r := range p.Rules {
		if r.On == on {
			out = append(out, r)
		}
	}

	return out
}

/*
 * Trigger -- просьбы соседей: единственное место, где чужое высказывание
 * что-то значит для калитки. Без правила действие соседа не применяется вовсе
 * (docs/inspector-actions.md, «Сторона получателя»).
 */
type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
	/*
	 * ReauthAfter -- возраст сессии, с которого просьба reauth действует.
	 * Сессия моложе -- клиент только что доказал, кто он, и гонять его на
	 * форму по той же просьбе значило бы зациклить вход: отправитель шлёт
	 * действие на каждом запросе и не знает, что вход уже случился.
	 * Ноль -- свежесть не проверяется, reauth действует всегда.
	 */
	ReauthAfter Duration `yaml:"reauth_after"`
}

/*
 * PriorRule -- что мы принимаем от соседа. Правило не умеет срабатывать на
 * число соседа из prior: score -- внутренняя шкала соседа без обещания
 * стабильности между версиями, и «мне этого достаточно» говорит отправитель
 * действием, а не получатель по чужому числу.
 *
 * Числовые глаголы (threshold, note) калитка не применяет -- у неё нет ни
 * своего порога, ни памяти про субъектов, и правило с таким глаголом не
 * грузится.
 */
type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	// Apply -- какие оси правило принимает. Без ключа -- любая допустимая при
	// этих глаголах.
	Apply []string `yaml:"apply"`
	Codes []string `yaml:"codes"`
}

// Accepts -- принимает ли правило этот глагол.
func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

// WantsAxis -- проходит ли ось через фильтр правила. Пустой список означает
// "любая допустимая при этих глаголах".
func (r PriorRule) WantsAxis(axis string) bool {
	if len(r.Apply) == 0 {
		return true
	}

	for _, a := range r.Apply {
		if a == axis {
			return true
		}
	}

	return false
}

// WantsCode -- проходит ли повод действия через фильтр правила. Пустой список
// означает "любой повод", в том числе отсутствующий.
func (r PriorRule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

/*
 * axesOf -- какие оси имеют смысл при этом глаголе. Та же матрица, что в
 * модуле: правило с несовместимой парой никогда не сработает, а правило,
 * которое никогда не срабатывает, -- опечатка, а не политика.
 */
func axesOf(verb string) []string {
	switch verb {
	case protocol.DoReauth:
		return []string{protocol.ApplySession}

	case protocol.DoNote:
		return []string{
			protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession,
		}

	/*
	 * Глаголы, которые инспектор не принимает (их отвергает загрузчик), но
	 * матрица держится полной: она сверяется со схемой провода, и ось,
	 * забытая здесь, читалась бы как расхождение с проводом. У управляющих
	 * ось -- срок (до конца транзакции либо соединения кадров), у глаголов
	 * записи -- какая запись (запроса либо ответа).
	 */
	case protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote:
		return []string{protocol.ApplyRequest, protocol.ApplyConn}

	case protocol.DoAudit, protocol.DoArchive:
		return []string{protocol.ApplyRequest, protocol.ApplyResponse}

	default:
		// challenge, threshold, skip, mutate, mark -- про этот запрос.
		return []string{protocol.ApplyRequest}
	}
}

func axisFits(verbs []string, axis string) bool {
	for _, v := range verbs {
		for _, a := range axesOf(v) {
			if a == axis {
				return true
			}
		}
	}

	return false
}

/*
 * validatePrior -- ограничения загрузчика, те же по духу, что у капчи. Модель
 * угрозы одна: один инспектор скомпрометирован или сломан. Тихий адресный
 * обход защиты хуже громкой общей аварии, поэтому послабление (skip) требует
 * имени отправителя, ужесточение (reauth) -- нет.
 */
func validatePrior(i int, r PriorRule) error {
	if r.From == "" {
		return fmt.Errorf("trigger.prior[%d]: from is empty (use %q for any)",
			i, AnyInspector)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("trigger.prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case protocol.DoReauth, protocol.DoSkip:

		case protocol.DoChallenge, protocol.DoThreshold, protocol.DoNote:
			// Чужие глаголы: challenge проводит капча, порог и память про
			// субъектов у калитки отсутствуют. Правило, которое никогда не
			// сработает, -- опечатка, а не политика.
			return fmt.Errorf("trigger.prior[%d]: %q is not ours to apply",
				i, verb)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown verb %q", i, verb)
		}
	}

	for _, axis := range r.Apply {
		switch axis {
		case protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession:

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown axis %q", i, axis)
		}

		if !axisFits(r.Accept, axis) {
			return fmt.Errorf("trigger.prior[%d]: axis %q never occurs with %v",
				i, axis, r.Accept)
		}
	}

	if r.From != AnyInspector {
		return nil
	}

	if r.Accepts(protocol.DoSkip) {
		return fmt.Errorf("trigger.prior[%d]: %q needs a named sender: it "+
			"always weakens", i, protocol.DoSkip)
	}

	return nil
}

type Gate struct {
	RedirectMethods []string `yaml:"redirect_methods"`
	RedirectStatus  int      `yaml:"redirect_status"`
	DenyResponse    string   `yaml:"deny_response"`
	HTMLOnly        bool     `yaml:"html_only"`

	/*
	 * Допуск по группам: вошедший обязан состоять хотя бы в одной из
	 * перечисленных. Пусто -- достаточно самого факта входа, и это обычное
	 * состояние профиля.
	 *
	 * Проверяется по сессии, а не на входе, и это единственное место, где
	 * такая проверка вообще работает: профиль «только admins» принимает
	 * сессию, выданную формой общего источника, и никакого входа у себя не
	 * видит. Групповой фильтр провайдера (providers.ldap.groups) такую сессию
	 * не рассматривает вовсе.
	 *
	 * Группы едут в сессии снимком на момент входа: вычеркнутый из группы
	 * теряет допуск со следующим входом либо сразу -- отзывом sid.
	 */
	Groups []string `yaml:"groups"`

	/*
	 * Запись каталога отказов для чужой группы. Отдельная от deny_response,
	 * потому что говорит другое: тот -- 401 «войдите», этот -- 403 «вошли, но
	 * не сюда». Одна запись на оба случая врала бы вошедшему.
	 */
	ForbiddenResponse string `yaml:"forbidden_response"`

	/*
	 * Форма прямо на месте вместо увода на неё редиректом. false -- прежнее
	 * поведение: навигационный запрос без сессии получает 30x на login.uri.
	 * true -- инспектор выписывает билет, берёт форму у auth-http внутренним
	 * запросом, кладёт её в обменник и отвечает deny с секцией rewrite; модуль
	 * отдаёт объект телом ответа на том же URI с кодом записи deny_response.
	 * Ни записи каталога, ни прокси-локации для этого не нужно.
	 *
	 * Зачем так: редирект уводит браузер на login.uri абсолютным адресом,
	 * который nginx достраивает портом своего listen, и за терминатором TLS
	 * или нестандартным портом клиент уезжает не туда. Форма на месте адреса
	 * не меняет -- ни истории, ни кэша, ни промаха по порту.
	 */
	Inline bool `yaml:"inline"`

	// Deprecated: прежний рычаг того же режима -- имя записи каталога, чья
	// страница проксировала на форму. Непустое значение читается как
	// inline: true одно поколение и больше ничего не значит.
	FormResponse string `yaml:"form_response"`
}

/* --- умолчания ------------------------------------------------------------- */

// profileDefaults -- то, что не спрашивают у оператора.
func profileDefaults(name string) *Profile {
	return &Profile{
		Name: name,
		Mode: ModeEnforce,
		/*
		 * Правил приёма по умолчанию нет: калитка без единого правила никого
		 * не слушает, и это обычное состояние. Свежесть -- пять минут: только
		 * что вошедшего по той же просьбе на форму не возвращаем.
		 */
		Trigger: Trigger{
			ReauthAfter: Duration(5 * time.Minute),
		},
		Gate: Gate{
			RedirectMethods:   []string{"GET", "HEAD"},
			RedirectStatus:    303,
			DenyResponse:      "auth_required",
			ForbiddenResponse: "auth_forbidden",
			HTMLOnly:          true,
		},
	}
}

/* --- разбор ---------------------------------------------------------------- */

// ParseProfile разбирает profile.yaml поверх умолчаний.
func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := profileDefaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	return p, nil
}

/* --- проверка -------------------------------------------------------------- */

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	/*
	 * Источник обязателен всюду, кроме off: и enforce, и observe открывают
	 * сессии, а без источника непонятно даже, какую куку читать. Существование
	 * названного источника проверяет реестр -- у одного файла соседей не видно.
	 */
	if p.Mode != ModeOff && p.Source == "" {
		return fmt.Errorf("source is empty: the gate cannot check sessions without one")
	}

	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

	for i, r := range p.Rules {
		if err := validateEventRule(i, r); err != nil {
			return err
		}
	}

	switch p.Gate.RedirectStatus {
	case 302, 303, 307:
	default:
		return fmt.Errorf("gate.redirect_status must be 302, 303 or 307, got %d",
			p.Gate.RedirectStatus)
	}

	if p.Gate.DenyResponse == "" {
		return fmt.Errorf("gate.deny_response is empty: the module needs a catalog name")
	}

	for i, g := range p.Gate.Groups {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("gate.groups[%d] is empty", i)
		}
	}

	if len(p.Gate.Groups) > 0 && p.Gate.ForbiddenResponse == "" {
		return fmt.Errorf("gate.forbidden_response is empty: a session " +
			"without the group is denied, and the module needs a catalog name for it")
	}

	for i, m := range p.Gate.RedirectMethods {
		if m != strings.ToUpper(m) {
			return fmt.Errorf("gate.redirect_methods[%d]: method must be upper case, got %q",
				i, m)
		}
	}

	// Прежний рычаг режима «телом ответа» -- одно поколение как синоним.
	if p.Gate.FormResponse != "" {
		p.Gate.Inline = true
	}

	return nil
}

// FormInline -- отдавать ли форму телом ответа вместо редиректа на неё.
func (p *Profile) FormInline() bool { return p.Gate.Inline }

/*
 * OwnPath -- запрос к самой форме источника: страница, POST входа, renew и
 * статика под login.uri. Вход на них -- рекурсия, и инспектор на этой локации
 * отвечает allow. Так адрес формы не обязан быть локейшеном без инспекторов:
 * остальные (списки адресов, лимиты, modsec) там только к месту.
 */
func (p *Profile) OwnPath(uri string) bool {
	if p.Src == nil {
		return false
	}

	/*
	 * У провайдера app свои адреса входа и выхода -- приложения: POST формы
	 * приходит без доверенной куки по построению, и калитка, которая его не
	 * пускает, не даёт войти никому.
	 */
	if p.Src.Learns() {
		l := p.Src.Providers.App.Learn

		if uri == l.Login.URI || (l.Logout.URI != "" && uri == l.Logout.URI) {
			return true
		}
	}

	if p.Src.Login.URI == "" {
		return false
	}

	base := p.Src.Login.URI

	if uri == base {
		return true
	}

	return strings.HasPrefix(uri, strings.TrimRight(base, "/")+"/")
}

/* --- запросы к профилю ----------------------------------------------------- */

// RedirectsMethod -- уводить ли этот метод на форму. Всё, что не уводим,
// получает 401: редирект на не-идемпотентном методе теряет тело.
func (p *Profile) RedirectsMethod(method string) bool {
	for _, m := range p.Gate.RedirectMethods {
		if m == method {
			return true
		}
	}

	return false
}

/*
 * Allows -- пускает ли профиль вошедшего с такими группами.
 *
 * Пустой список допуска означает «групп не спрашиваем», а не «никого не
 * пускаем»: иначе профиль без секции закрыл бы вход всем и выглядел бы при
 * этом исправным. Совпадения хватает одного -- «состоит хотя бы в одной».
 *
 * Регистр не различается: каталоги отдают CN как им удобно, а список контура
 * пишут руками, и вход, работающий через раз из-за заглавной буквы, -- это
 * два часа поисков на ровном месте.
 */
func (p *Profile) Allows(groups []string) bool {
	return GroupsAllow(groups, p.Gate.Groups)
}

// GroupsAllow -- то же сравнение для провайдеров: у ldap и ntlm свой фильтр,
// на входе, и правила совпадения у них обязаны быть те же.
func GroupsAllow(groups, want []string) bool {
	if len(want) == 0 {
		return true
	}

	for _, w := range want {
		for _, g := range groups {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(w)) {
				return true
			}
		}
	}

	return false
}
