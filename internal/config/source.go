package config

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProviderLocal = "local"
	ProviderCode  = "code"
	ProviderLDAP  = "ldap"
	ProviderNTLM  = "ntlm"
	ProviderJWT   = "jwt"
	ProviderApp   = "app"

	JWTAlgNone = "none"

	FieldBodyForm = "body.form"
	FieldBodyJSON = "body.json"
	FieldArgs     = "args"
	FieldHeader   = "header"

	CodeTOTP   = "totp"
	CodeStatic = "static"

	BindUPN        = "upn"
	BindDNTemplate = "dn_template"
	BindSearch     = "search"

	RosterRedis  = "redis"
	RosterMemory = "memory"

	BindNet = "subnet"
	BindUA  = "ua"
)

type Source struct {
	Name string `yaml:"-"`

	Login    Login    `yaml:"login"`
	Session  Session  `yaml:"session"`
	Ticket   Ticket   `yaml:"ticket"`
	List     List     `yaml:"list"`
	Upstream Upstream `yaml:"upstream"`

	Provider  string    `yaml:"provider"`
	Identity  Identity  `yaml:"identity"`
	Providers Providers `yaml:"providers"`
	Lockout   Lockout   `yaml:"lockout"`
	Roster    Roster    `yaml:"roster"`

	Users map[string]*User `yaml:"-"`

	LoginPage *template.Template `yaml:"-"`
}

type Login struct {
	URI   string `yaml:"uri"`
	Title string `yaml:"title"`
	Note  string `yaml:"note"`
}

type Session struct {
	Cookie     string   `yaml:"cookie"`
	TTL        Duration `yaml:"ttl"`
	RenewAfter Duration `yaml:"renew_after"`
	MaxTTL     Duration `yaml:"max_ttl"`
	Bind       []string `yaml:"bind"`
	Subnet     Subnet   `yaml:"subnet"`
}

type Subnet struct {
	V4 int `yaml:"v4"`
	V6 int `yaml:"v6"`
}

type Ticket struct {
	Cookie string   `yaml:"cookie"`
	TTL    Duration `yaml:"ttl"`
}

type List struct {
	Sessions string   `yaml:"sessions"`
	Cookie   string   `yaml:"cookie"`
	TTL      Duration `yaml:"ttl"`
	Origin   string   `yaml:"origin"`
	Grace    Duration `yaml:"grace"`
}

func (l List) Enabled() bool { return l.Sessions != "" }

type Upstream struct {
	User   string   `yaml:"user"`
	Groups string   `yaml:"groups"`
	Method string   `yaml:"method"`
	Cookie string   `yaml:"cookie"`
	TTL    Duration `yaml:"ttl"`
}

type Identity struct {
	From string `yaml:"from"`
}

type Providers struct {
	Local *LocalProvider `yaml:"local"`
	Code  *CodeProvider  `yaml:"code"`
	LDAP  *LDAPProvider  `yaml:"ldap"`
	NTLM  *NTLMProvider  `yaml:"ntlm"`
	JWT   *JWTProvider   `yaml:"jwt"`
	App   *AppProvider   `yaml:"app"`
}

type JWTProvider struct {
	Cookie string    `yaml:"cookie"`
	Header string    `yaml:"header"`
	Prefix string    `yaml:"prefix"`
	Verify JWTVerify `yaml:"verify"`
	Claims JWTClaims `yaml:"claims"`

	Key []byte `yaml:"-"`
}

type JWTVerify struct {
	Alg       string   `yaml:"alg"`
	KeyFile   string   `yaml:"key_file"`
	SecretEnv string   `yaml:"secret_env"`
	Issuer    string   `yaml:"issuer"`
	Audience  string   `yaml:"audience"`
	Leeway    Duration `yaml:"leeway"`
}

type JWTClaims struct {
	User    string `yaml:"user"`
	Session string `yaml:"session"`
	Groups  string `yaml:"groups"`
	Issued  string `yaml:"issued"`
	Expiry  string `yaml:"expiry"`
}

type AppProvider struct {
	Cookie string   `yaml:"cookie"`
	Learn  AppLearn `yaml:"learn"`
}

type AppLearn struct {
	Login   AppRoute   `yaml:"login"`
	Logout  AppRoute   `yaml:"logout"`
	Success AppSuccess `yaml:"success"`
	User    AppField   `yaml:"user"`
}

type AppRoute struct {
	URI    string `yaml:"uri"`
	Method string `yaml:"method"`
}

type AppSuccess struct {
	Status    []int         `yaml:"status"`
	CookieNew *bool         `yaml:"cookie_new"`
	JSON      *AppJSONCheck `yaml:"json"`
}

type AppJSONCheck struct {
	Path   string `yaml:"path"`
	Equals string `yaml:"equals"`
}

type AppField struct {
	From  string `yaml:"from"`
	Field string `yaml:"field"`
}

func (s AppSuccess) RequiresCookieNew() bool {
	return s.CookieNew == nil || *s.CookieNew
}

type LocalProvider struct {
	Users string `yaml:"users"`
}

type CodeProvider struct {
	Kind   string   `yaml:"kind"`
	Digits int      `yaml:"digits"`
	Period Duration `yaml:"period"`
	Skew   int      `yaml:"skew"`
	Users  string   `yaml:"users"`
	Codes  []string `yaml:"codes"`
}

type LDAPProvider struct {
	URL        string     `yaml:"url"`
	StartTLS   bool       `yaml:"start_tls"`
	Bind       string     `yaml:"bind"`
	UPNSuffix  string     `yaml:"upn_suffix"`
	DNTemplate string     `yaml:"dn_template"`
	Timeout    Duration   `yaml:"timeout"`
	Groups     []string   `yaml:"groups"`
	Search     LDAPSearch `yaml:"search"`
	TLS        LDAPTLS    `yaml:"tls"`
}

type LDAPSearch struct {
	Base          string `yaml:"base"`
	Filter        string `yaml:"filter"`
	BindDN        string `yaml:"bind_dn"`
	PasswordEnv   string `yaml:"password_env"`
	PasswordStore string `yaml:"password_store"`
}

type LDAPTLS struct {
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type NTLMProvider struct {
	URL      string     `yaml:"url"`
	Domain   string     `yaml:"domain"`
	Timeout  Duration   `yaml:"timeout"`
	StartTLS bool       `yaml:"start_tls"`
	Groups   []string   `yaml:"groups"`
	Search   LDAPSearch `yaml:"search"`
	TLS      LDAPTLS    `yaml:"tls"`
}

type Lockout struct {
	Attempts int      `yaml:"attempts"`
	Window   Duration `yaml:"window"`
	Lock     Duration `yaml:"lock"`
}

type Roster struct {
	Store  string `yaml:"store"`
	Prefix string `yaml:"prefix"`
}

type User struct {
	Login     string   `yaml:"login"`
	Password  string   `yaml:"password"`
	TOTP      string   `yaml:"totp"`
	TOTPStore string   `yaml:"totp_store"`
	Groups    []string `yaml:"groups"`
	Enabled   *bool    `yaml:"enabled"`
	Display   string   `yaml:"display"`
}

func (u *User) Active() bool { return u.Enabled == nil || *u.Enabled }

type usersFile struct {
	Users []*User `yaml:"users"`
}

func sourceDefaults(name string) *Source {
	return &Source{
		Name: name,
		Session: Session{
			Cookie: "waf_sid_" + name,
			TTL:    Duration(8 * time.Hour),
			Bind:   []string{BindNet, BindUA},
			Subnet: Subnet{V4: 24, V6: 64},
		},
		Ticket: Ticket{
			Cookie: "waf_lgn_" + name,
			TTL:    Duration(10 * time.Minute),
		},
		List: List{
			Cookie: "waf_sess",
		},
		Upstream: Upstream{
			User:   "X-WAF-User",
			Groups: "X-WAF-Groups",
			Method: "X-WAF-Auth",
		},
		Lockout: Lockout{
			Attempts: 5,
			Window:   Duration(10 * time.Minute),
			Lock:     Duration(15 * time.Minute),
		},
		Roster: Roster{
			Store:  RosterRedis,
			Prefix: "auth:",
		},
	}
}

func ParseSource(name string, raw []byte) (*Source, error) {
	src := sourceDefaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(src); err != nil {
		return nil, fmt.Errorf("source %s: %w", name, err)
	}

	src.Name = name

	return src, nil
}

func ParseUsers(raw []byte) (map[string]*User, error) {
	var file usersFile

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(&file); err != nil {
		return nil, err
	}

	out := make(map[string]*User, len(file.Users))

	for i, u := range file.Users {
		if u == nil || strings.TrimSpace(u.Login) == "" {
			return nil, fmt.Errorf("users[%d]: login is empty", i)
		}

		key := strings.ToLower(strings.TrimSpace(u.Login))

		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("users[%d]: login %q is declared twice", i, u.Login)
		}

		if !isBcrypt(u.Password) {
			return nil, fmt.Errorf("users[%d]: password of %q is not a bcrypt hash "+
				"(htpasswd -B); plain passwords are rejected", i, u.Login)
		}

		if u.TOTP != "" && u.TOTPStore != "" {
			return nil, fmt.Errorf("users[%d]: totp and totp_store are mutually "+
				"exclusive for %q", i, u.Login)
		}

		out[key] = u
	}

	return out, nil
}

func isBcrypt(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

func (s *Source) Validate() error {
	if s.Login.URI == "" && !s.External() {
		return fmt.Errorf("login.uri is empty: a source without a form cannot log anyone in")
	}

	if s.Login.URI != "" {
		if !strings.HasPrefix(s.Login.URI, "/") {
			return fmt.Errorf("login.uri must be an absolute path, got %q", s.Login.URI)
		}

		if strings.Contains(s.Login.URI, "?") || strings.Contains(s.Login.URI, "#") {
			return fmt.Errorf("login.uri must not carry a query or fragment, got %q",
				s.Login.URI)
		}
	}

	if s.Session.Cookie == "" || s.Ticket.Cookie == "" {
		return fmt.Errorf("session.cookie and ticket.cookie must not be empty")
	}

	if s.Session.Cookie == s.Ticket.Cookie {
		return fmt.Errorf("session.cookie and ticket.cookie must differ")
	}

	if s.Upstream.Cookie != "" {
		if s.Upstream.Cookie == s.Session.Cookie || s.Upstream.Cookie == s.Ticket.Cookie {
			return fmt.Errorf("upstream.cookie must differ from the gate cookies")
		}

		if s.Upstream.TTL < 0 {
			return fmt.Errorf("upstream.ttl must not be negative")
		}
	}

	if s.Session.TTL <= 0 {
		return fmt.Errorf("session.ttl must be positive")
	}

	if s.Session.RenewAfter != 0 && s.Session.RenewAfter >= s.Session.TTL {
		return fmt.Errorf("session.renew_after must be shorter than session.ttl")
	}

	if s.Session.MaxTTL != 0 && s.Session.MaxTTL < s.Session.TTL {
		return fmt.Errorf("session.max_ttl must not be shorter than session.ttl")
	}

	for _, b := range s.Session.Bind {
		if b != BindNet && b != BindUA {
			return fmt.Errorf("session.bind: expected subnet or ua, got %q", b)
		}
	}

	if s.Session.Subnet.V4 < 0 || s.Session.Subnet.V4 > 32 {
		return fmt.Errorf("session.subnet.v4 must be within 0..32, got %d", s.Session.Subnet.V4)
	}

	if s.Session.Subnet.V6 < 0 || s.Session.Subnet.V6 > 128 {
		return fmt.Errorf("session.subnet.v6 must be within 0..128, got %d", s.Session.Subnet.V6)
	}

	if s.Ticket.TTL <= 0 {
		return fmt.Errorf("ticket.ttl must be positive")
	}

	if s.List.Enabled() {
		if s.List.TTL <= 0 {
			s.List.TTL = s.Session.TTL
		}

		if s.List.TTL > s.Session.TTL {
			return fmt.Errorf("list.ttl must not outlive session.ttl")
		}

		if s.List.Grace <= 0 {
			s.List.Grace = Duration(2 * time.Second)
		}

		if s.List.Grace > Duration(5*time.Minute) {
			return fmt.Errorf("list.grace must not exceed 5m: it is a window "+
				"for the sequencer round-trip, not a second session ttl, got %s",
				s.List.Grace.D().String())
		}

		if strings.ContainsAny(s.List.Sessions, " .>*") {
			return fmt.Errorf("list.sessions must be a plain dataset name, got %q",
				s.List.Sessions)
		}

		if s.List.Cookie == "" {
			return fmt.Errorf("list.cookie is empty: the dataset is keyed by it")
		}

		if s.List.Cookie == s.Session.Cookie || s.List.Cookie == s.Ticket.Cookie {
			return fmt.Errorf("list.cookie must differ from session.cookie and ticket.cookie")
		}
	}

	switch s.Roster.Store {
	case RosterRedis, RosterMemory:
	default:
		return fmt.Errorf("roster.store must be redis or memory, got %q", s.Roster.Store)
	}

	if s.Lockout.Attempts < 0 {
		return fmt.Errorf("lockout.attempts must not be negative")
	}

	return s.validateProvider()
}

func (s *Source) validateProvider() error {
	if s.Identity.From == s.Name && s.Identity.From != "" {
		return fmt.Errorf("identity.from must name another source")
	}

	if s.Provider == "" {
		return fmt.Errorf("provider is empty: a form without a provider lets everyone in")
	}

	switch s.Provider {
	case ProviderLocal:
		if s.Providers.Local == nil || s.Providers.Local.Users == "" {
			return fmt.Errorf("provider local: providers.local.users is not set")
		}

	case ProviderCode:
		if err := s.validateCode(); err != nil {
			return err
		}

	case ProviderLDAP:
		if err := s.validateLDAP(); err != nil {
			return err
		}

	case ProviderNTLM:
		if s.Providers.NTLM == nil || s.Providers.NTLM.URL == "" {
			return fmt.Errorf("provider ntlm: providers.ntlm.url is not set")
		}

		if s.Providers.NTLM.Domain == "" {
			return fmt.Errorf("provider ntlm: providers.ntlm.domain is not set")
		}

		if err := validateSearchSecret(s.Providers.NTLM.Search,
			"providers.ntlm.search"); err != nil {
			return err
		}

	case ProviderJWT:
		if err := s.validateJWT(); err != nil {
			return err
		}

	case ProviderApp:
		if err := s.validateApp(); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown provider %q", s.Provider)
	}

	if s.Identity.From != "" && !(s.Provider == ProviderCode &&
		s.Providers.Code != nil && s.Providers.Code.Kind == CodeTOTP) {
		return fmt.Errorf("identity.from is only for provider code with kind totp")
	}

	return nil
}

func (s *Source) validateCode() error {
	c := s.Providers.Code
	if c == nil {
		return fmt.Errorf("provider code: providers.code is not set")
	}

	switch c.Kind {
	case CodeTOTP:
		if c.Digits < 6 || c.Digits > 10 {
			return fmt.Errorf("providers.code.digits must be within 6..10, got %d", c.Digits)
		}

		if c.Period <= 0 {
			return fmt.Errorf("providers.code.period must be positive")
		}

		if c.Skew < 0 || c.Skew > 5 {
			return fmt.Errorf("providers.code.skew must be within 0..5, got %d", c.Skew)
		}

		if s.Identity.From == "" {
			return fmt.Errorf("providers.code with kind totp needs identity.from: " +
				"the source of the gate that establishes the identity")
		}

		if c.Users == "" {
			return fmt.Errorf("providers.code.users is not set: totp secrets live there")
		}

	case CodeStatic:
		if len(c.Codes) == 0 {
			return fmt.Errorf("providers.code.codes is empty")
		}

		for j, h := range c.Codes {
			if !isBcrypt(h) {
				return fmt.Errorf("providers.code.codes[%d] is not a bcrypt hash "+
					"(htpasswd -nBC 12); plain codes are rejected", j)
			}
		}

	default:
		return fmt.Errorf("providers.code.kind must be totp or static, got %q", c.Kind)
	}

	return nil
}

func (s *Source) validateLDAP() error {
	l := s.Providers.LDAP
	if l == nil || l.URL == "" {
		return fmt.Errorf("provider ldap: providers.ldap.url is not set")
	}

	switch l.Bind {
	case BindUPN:
		if l.UPNSuffix == "" {
			return fmt.Errorf("providers.ldap.upn_suffix is required for bind: upn")
		}

	case BindDNTemplate:
		if !strings.Contains(l.DNTemplate, "%s") {
			return fmt.Errorf("providers.ldap.dn_template must contain %%s")
		}

	case BindSearch:
		if l.Search.Base == "" || !strings.Contains(l.Search.Filter, "%s") {
			return fmt.Errorf("providers.ldap.search needs base and a filter with %%s")
		}

	default:
		return fmt.Errorf("providers.ldap.bind must be upn, dn_template or search, got %q",
			l.Bind)
	}

	if len(l.Groups) > 0 && l.Bind != BindSearch {
		return fmt.Errorf("providers.ldap.groups requires bind: search -- " +
			"membership is read from the directory entry")
	}

	return validateSearchSecret(l.Search, "providers.ldap.search")
}

var jwtAlgs = map[string]bool{
	"HS256": true, "HS384": true, "HS512": true,
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true,
	JWTAlgNone: true,
}

func (s *Source) validateJWT() error {
	j := s.Providers.JWT
	if j == nil {
		return fmt.Errorf("provider jwt: providers.jwt is not set")
	}

	if (j.Cookie == "") == (j.Header == "") {
		return fmt.Errorf("providers.jwt: exactly one of cookie or header must name " +
			"where the token lives")
	}

	if j.Cookie != "" && (j.Cookie == s.Session.Cookie || j.Cookie == s.Ticket.Cookie) {
		return fmt.Errorf("providers.jwt.cookie must differ from the gate cookies")
	}

	if j.Verify.Alg == "" {
		return fmt.Errorf("providers.jwt.verify.alg is empty: name the algorithm " +
			"or none for an unverified parse")
	}

	if !jwtAlgs[j.Verify.Alg] {
		return fmt.Errorf("providers.jwt.verify.alg: unsupported %q", j.Verify.Alg)
	}

	file := j.Verify.KeyFile != ""
	env := j.Verify.SecretEnv != ""

	switch {
	case j.Verify.Alg == JWTAlgNone:
		if file || env {
			return fmt.Errorf("providers.jwt.verify: alg none does not take a key")
		}

	case file && env:
		return fmt.Errorf("providers.jwt.verify: key_file and secret_env are mutually exclusive")

	case !file && !env:
		return fmt.Errorf("providers.jwt.verify: alg %s needs key_file or secret_env",
			j.Verify.Alg)

	case env && !strings.HasPrefix(j.Verify.Alg, "HS"):
		return fmt.Errorf("providers.jwt.verify: secret_env is for HMAC algorithms; "+
			"%s takes a public key in key_file", j.Verify.Alg)
	}

	if j.Verify.Leeway < 0 {
		return fmt.Errorf("providers.jwt.verify.leeway must not be negative")
	}

	if j.Claims.User == "" {
		j.Claims.User = "sub"
	}

	if j.Claims.Session == "" {
		j.Claims.Session = "sid"
	}

	if j.Claims.Issued == "" {
		j.Claims.Issued = "iat"
	}

	if j.Claims.Expiry == "" {
		j.Claims.Expiry = "exp"
	}

	return nil
}

func (s *Source) validateApp() error {
	a := s.Providers.App
	if a == nil {
		return fmt.Errorf("provider app: providers.app is not set")
	}

	if a.Cookie == "" {
		return fmt.Errorf("providers.app.cookie is empty: name the application's session cookie")
	}

	if a.Cookie == s.Session.Cookie || a.Cookie == s.Ticket.Cookie || a.Cookie == s.List.Cookie {
		return fmt.Errorf("providers.app.cookie must differ from the gate cookies")
	}

	if !s.List.Enabled() {
		return fmt.Errorf("provider app needs list.sessions: the list is the set of trusted sessions")
	}

	l := &a.Learn

	if l.Login.URI == "" {
		return fmt.Errorf("providers.app.learn.login.uri is empty: where does the application log in")
	}

	for _, r := range []struct {
		name  string
		route *AppRoute
	}{{"login", &l.Login}, {"logout", &l.Logout}} {
		if r.route.URI == "" {
			continue
		}

		if !strings.HasPrefix(r.route.URI, "/") || strings.ContainsAny(r.route.URI, "?#") {
			return fmt.Errorf("providers.app.learn.%s.uri must be an absolute path without "+
				"query, got %q", r.name, r.route.URI)
		}

		if r.route.Method == "" {
			r.route.Method = "POST"
		}

		if r.route.Method != strings.ToUpper(r.route.Method) {
			return fmt.Errorf("providers.app.learn.%s.method must be upper case, got %q",
				r.name, r.route.Method)
		}
	}

	switch l.User.From {
	case FieldBodyForm, FieldBodyJSON, FieldArgs, FieldHeader:
	case "":
		return fmt.Errorf("providers.app.learn.user.from is empty: body.form, body.json, args or header")
	default:
		return fmt.Errorf("providers.app.learn.user.from: unknown %q", l.User.From)
	}

	if l.User.Field == "" {
		return fmt.Errorf("providers.app.learn.user.field is empty: which field carries the login")
	}

	if len(l.Success.Status) == 0 {
		l.Success.Status = []int{200, 302, 303}
	}

	for _, code := range l.Success.Status {
		if code < 100 || code > 599 {
			return fmt.Errorf("providers.app.learn.success.status: %d is not an HTTP status", code)
		}
	}

	if l.Success.JSON != nil && l.Success.JSON.Path == "" {
		return fmt.Errorf("providers.app.learn.success.json.path is empty")
	}

	return nil
}

func validateSearchSecret(s LDAPSearch, path string) error {
	if s.BindDN == "" {
		return nil
	}

	env := s.PasswordEnv != ""
	store := s.PasswordStore != ""

	if env && store {
		return fmt.Errorf("%s: password_env and password_store are mutually exclusive",
			path)
	}

	if !env && !store {
		return fmt.Errorf("%s: bind_dn needs password_env or password_store", path)
	}

	return nil
}

func (s *Source) BindsNet() bool { return s.hasBind(BindNet) }
func (s *Source) BindsUA() bool  { return s.hasBind(BindUA) }

func (s *Source) External() bool {
	return s.Provider == ProviderJWT || s.Provider == ProviderApp
}

func (s *Source) SessionCookie() string {
	switch s.Provider {
	case ProviderJWT:
		if s.Providers.JWT != nil {
			return s.Providers.JWT.Cookie
		}

		return ""

	case ProviderApp:
		if s.Providers.App != nil {
			return s.Providers.App.Cookie
		}

		return ""
	}

	return s.Session.Cookie
}

func (s *Source) Learns() bool {
	return s.Provider == ProviderApp && s.Providers.App != nil &&
		s.Providers.App.Learn.Login.URI != ""
}

func (s *Source) hasBind(kind string) bool {
	for _, b := range s.Session.Bind {
		if b == kind {
			return true
		}
	}

	return false
}

func (s *Source) UsersFile() string {
	switch s.Provider {
	case ProviderLocal:
		if s.Providers.Local != nil {
			return s.Providers.Local.Users
		}

	case ProviderCode:
		if s.Providers.Code != nil && s.Providers.Code.Kind == CodeTOTP {
			return s.Providers.Code.Users
		}
	}

	return ""
}
