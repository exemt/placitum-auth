package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-auth/internal/overload"
	"github.com/exemt/placitum-auth/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	AnyInspector = "*"
)

const DefaultName = "default"

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
	Name string `yaml:"-"`

	Mode string `yaml:"mode"`

	Source string `yaml:"source"`

	Gate    Gate    `yaml:"gate"`
	Trigger Trigger `yaml:"trigger"`

	Rules []EventRule `yaml:"rules"`

	Src *Source `yaml:"-"`
}

const (
	OnAuthenticated = "authenticated"
	OnAnonymous     = "anonymous"
	OnInvalid       = "invalid"
	OnForbidden     = "forbidden"
	OnOverload      = overload.On
)

func askTravels(on string) bool {
	return on == OnAuthenticated || on == OnOverload
}

var eventCodeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

var eventNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type EventRule struct {
	On string `yaml:"on"`
	At *int   `yaml:"at"`

	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Group   string               `yaml:"group"`
	Set     string               `yaml:"set"`
	Marker  string               `yaml:"marker"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	List  string   `yaml:"list"`
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	Code string `yaml:"code"`
}

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
		if r.At != nil {
			return fmt.Errorf("%s: at is only for on: %s", at, OnOverload)
		}

	case OnOverload:
		if err := overload.Check(r.At); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}

	default:
		return fmt.Errorf("%s: on must be authenticated, anonymous, invalid, "+
			"forbidden or overload, got %q", at, r.On)
	}

	if (r.Do == "") == (r.List == "") {
		return fmt.Errorf("%s: exactly one of do or list", at)
	}

	if r.Do != "" {
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

func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

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

func (p *Profile) RulesFor(on string) []EventRule {
	var out []EventRule

	for _, r := range p.Rules {
		if r.On == on {
			out = append(out, r)
		}
	}

	return out
}

type Trigger struct {
	Prior       []PriorRule `yaml:"prior"`
	ReauthAfter Duration    `yaml:"reauth_after"`
}

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	Apply  []string `yaml:"apply"`
	Codes  []string `yaml:"codes"`
}

func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

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

func axesOf(verb string) []string {
	switch verb {
	case protocol.DoReauth:
		return []string{protocol.ApplySession}

	case protocol.DoNote:
		return []string{
			protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession,
		}

	case protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote:
		return []string{protocol.ApplyRequest, protocol.ApplyConn}

	case protocol.DoAudit, protocol.DoArchive:
		return []string{protocol.ApplyRequest, protocol.ApplyResponse}

	default:
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

	Groups []string `yaml:"groups"`

	ForbiddenResponse string `yaml:"forbidden_response"`

	Inline bool `yaml:"inline"`
}

func profileDefaults(name string) *Profile {
	return &Profile{
		Name: name,
		Mode: ModeEnforce,
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

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

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

	return nil
}

func (p *Profile) FormInline() bool { return p.Gate.Inline }

func (p *Profile) OwnPath(uri string) bool {
	if p.Src == nil {
		return false
	}

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

func (p *Profile) RedirectsMethod(method string) bool {
	for _, m := range p.Gate.RedirectMethods {
		if m == method {
			return true
		}
	}

	return false
}

func (p *Profile) Allows(groups []string) bool {
	return GroupsAllow(groups, p.Gate.Groups)
}

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
