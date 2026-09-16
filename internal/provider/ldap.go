package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/exemt/placitum-auth/internal/config"
)

const defaultLDAPTimeout = 3 * time.Second

type LDAP struct {
	Cfg     *config.LDAPProvider
	Secrets Secrets
}

func (*LDAP) Name() string { return config.ProviderLDAP }

func (*LDAP) Fields() []string { return []string{FieldLogin, FieldPassword} }

func (l *LDAP) Verify(ctx context.Context, c Credentials, id *Identity) (*Identity, error) {
	if l.Cfg == nil {
		return nil, ErrUnavailable
	}

	login := strings.TrimSpace(c.Login)

	if login == "" || c.Password == "" {
		return nil, ErrInvalid
	}

	conn, err := dial(ctx, l.Cfg.URL, l.Cfg.StartTLS, l.Cfg.TLS, l.Cfg.Timeout.D())
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	dn := ""
	entry := (*ldap.Entry)(nil)

	switch l.Cfg.Bind {
	case config.BindUPN:
		dn = login + l.Cfg.UPNSuffix

	case config.BindDNTemplate:
		dn = fmt.Sprintf(l.Cfg.DNTemplate, ldap.EscapeDN(login))

	case config.BindSearch:
		password, perr := servicePassword(ctx, l.Cfg.Search, l.Secrets)
		if perr != nil {
			return nil, perr
		}

		entry, err = lookup(conn, l.Cfg.Search, login, password)
		if err != nil {
			return nil, err
		}

		dn = entry.DN
	}

	if err := bind(conn, dn, c.Password); err != nil {
		return nil, err
	}

	groups := memberOf(entry)

	if l.Cfg.Bind == config.BindSearch && len(groups) == 0 && entry != nil {
		groups, err = l.reverse(ctx, entry.DN)
		if err != nil {
			return nil, err
		}
	}

	return finish(id, login, entry, groups, l.Cfg.Groups, "ldap")
}

func (l *LDAP) reverse(ctx context.Context, dn string) ([]string, error) {
	password, err := servicePassword(ctx, l.Cfg.Search, l.Secrets)
	if err != nil {
		return nil, err
	}

	conn, err := dial(ctx, l.Cfg.URL, l.Cfg.StartTLS, l.Cfg.TLS, l.Cfg.Timeout.D())
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	return reverseGroups(conn, l.Cfg.Search, dn, password)
}

type NTLM struct {
	Cfg     *config.NTLMProvider
	Secrets Secrets
}

func (*NTLM) Name() string { return config.ProviderNTLM }

func (*NTLM) Fields() []string { return []string{FieldLogin, FieldPassword} }

func (n *NTLM) Verify(ctx context.Context, c Credentials, id *Identity) (*Identity, error) {
	if n.Cfg == nil {
		return nil, ErrUnavailable
	}

	login := strings.TrimSpace(c.Login)

	domain := n.Cfg.Domain

	if d, user, ok := strings.Cut(login, `\`); ok {
		domain, login = d, user
	}

	if login == "" || c.Password == "" {
		return nil, ErrInvalid
	}

	conn, err := dial(ctx, n.Cfg.URL, n.Cfg.StartTLS, n.Cfg.TLS, n.Cfg.Timeout.D())
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	if err := ldapErr(conn.NTLMBind(domain, login, c.Password)); err != nil {
		return nil, err
	}

	var entry *ldap.Entry

	groups := []string(nil)

	if len(n.Cfg.Groups) > 0 || n.Cfg.Search.Base != "" {
		conn2, err := dial(ctx, n.Cfg.URL, n.Cfg.StartTLS, n.Cfg.TLS, n.Cfg.Timeout.D())
		if err != nil {
			return nil, err
		}

		defer conn2.Close()

		password, perr := servicePassword(ctx, n.Cfg.Search, n.Secrets)
		if perr != nil {
			return nil, perr
		}

		entry, err = lookup(conn2, n.Cfg.Search, login, password)
		if err != nil {
			return nil, err
		}

		groups = memberOf(entry)

		if len(groups) == 0 {
			groups, err = reverseGroups(conn2, n.Cfg.Search, entry.DN, password)
			if err != nil {
				return nil, err
			}
		}
	}

	return finish(id, login, entry, groups, n.Cfg.Groups, "ntlm")
}

func servicePassword(ctx context.Context, s config.LDAPSearch, sec Secrets) (
	string, error) {

	if s.BindDN == "" {
		return "", nil
	}

	if s.PasswordStore != "" {
		if sec == nil {
			return "", fmt.Errorf("%w: password_store needs the contour key",
				ErrUnavailable)
		}

		value, err := sec.Get(ctx, s.PasswordStore)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrUnavailable, err)
		}

		return value, nil
	}

	value := os.Getenv(s.PasswordEnv)
	if value == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrUnavailable, s.PasswordEnv)
	}

	return value, nil
}

func dial(ctx context.Context, url string, startTLS bool, tlsCfg config.LDAPTLS,
	timeout time.Duration) (*ldap.Conn, error) {

	if timeout <= 0 {
		timeout = defaultLDAPTimeout
	}

	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left > 0 && left < timeout {
			timeout = left
		}
	}

	cfg, err := tlsConfig(url, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, err)
	}

	conn, err := ldap.DialURL(url,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(cfg),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, err)
	}

	conn.SetTimeout(timeout)

	if startTLS {
		if err := conn.StartTLS(cfg); err != nil {
			conn.Close()

			return nil, fmt.Errorf("%w: start tls: %s", ErrUnavailable, err)
		}
	}

	return conn, nil
}

func tlsConfig(url string, cfg config.LDAPTLS) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // deliberate profile option
		ServerName:         hostOf(url),
	}

	if cfg.CAFile == "" {
		return out, nil
	}

	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", cfg.CAFile)
	}

	out.RootCAs = pool

	return out, nil
}

func hostOf(url string) string {
	rest := url

	if _, after, ok := strings.Cut(url, "://"); ok {
		rest = after
	}

	rest, _, _ = strings.Cut(rest, "/")

	if host, _, err := net.SplitHostPort(rest); err == nil {
		return host
	}

	return rest
}

func lookup(conn *ldap.Conn, s config.LDAPSearch, login, password string) (*ldap.Entry, error) {
	if err := serviceBind(conn, s, password); err != nil {
		return nil, err
	}

	req := ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false,
		fmt.Sprintf(s.Filter, ldap.EscapeFilter(login)),
		[]string{"dn", "displayName", "memberOf", "sAMAccountName"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, ldapErr(err)
	}

	if len(res.Entries) != 1 {
		return nil, ErrInvalid
	}

	return res.Entries[0], nil
}

func serviceBind(conn *ldap.Conn, s config.LDAPSearch, password string) error {
	if s.BindDN == "" {
		return nil
	}

	if password == "" {
		return fmt.Errorf("%w: service password is empty", ErrUnavailable)
	}

	if err := ldapErr(conn.Bind(s.BindDN, password)); err != nil {
		return fmt.Errorf("%w: service bind failed", ErrUnavailable)
	}

	return nil
}

func bind(conn *ldap.Conn, dn, password string) error {
	if dn == "" {
		return ErrInvalid
	}

	return ldapErr(conn.Bind(dn, password))
}

func memberOf(entry *ldap.Entry) []string {
	if entry == nil {
		return nil
	}

	return entry.GetAttributeValues("memberOf")
}

func reverseGroups(conn *ldap.Conn, s config.LDAPSearch, dn, password string) (
	[]string, error) {

	if s.Base == "" || dn == "" {
		return nil, nil
	}

	if err := serviceBind(conn, s, password); err != nil {
		return nil, err
	}

	req := ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"+
			"(|(member="+ldap.EscapeFilter(dn)+")(uniqueMember="+ldap.EscapeFilter(dn)+")))",
		[]string{"dn", "cn"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, ldapErr(err)
	}

	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, e.DN)
	}

	return out, nil
}

func finish(id *Identity, login string, entry *ldap.Entry, groups, want []string,
	amr string) (*Identity, error) {

	if id == nil {
		id = &Identity{}
	}

	subject := login

	if entry != nil {
		if v := entry.GetAttributeValue("sAMAccountName"); v != "" {
			subject = v
		}

		if v := entry.GetAttributeValue("displayName"); v != "" {
			id.Display = v
		}
	}

	if !allowed(groups, want) {
		return nil, ErrNotAllowed
	}

	id.Subject = subject
	id.Groups = append(id.Groups, shortNames(groups)...)
	id.with(amr)

	return id, nil
}

func shortNames(dns []string) []string {
	out := make([]string, 0, len(dns))

	for _, dn := range dns {
		first, _, _ := strings.Cut(dn, ",")

		if _, cn, ok := strings.Cut(first, "="); ok {
			out = append(out, cn)
			continue
		}

		out = append(out, first)
	}

	return out
}

func ldapErr(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials),
		ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject),
		ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidDNSyntax):
		return ErrInvalid

	case ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights),
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform):
		return ErrNotAllowed
	}

	var ntlmErr *ldap.Error
	if errors.As(err, &ntlmErr) && ntlmErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return ErrInvalid
	}

	return fmt.Errorf("%w: %s", ErrUnavailable, err)
}
