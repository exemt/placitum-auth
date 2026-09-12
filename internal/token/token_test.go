package token

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T, secret string) *Key {
	t.Helper()

	k, err := NewKey([]byte(secret))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}

	return k
}

var now = time.Unix(1_700_000_000, 0)

func TestSessionRoundTrip(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")

	want := &Session{
		SID:    "abc",
		Sub:    "ivanov",
		Issued: now.Unix(),
		Expiry: now.Add(time.Hour).Unix(),
		Scope:  "default",
		Net:    "203.0.113.0/24",
		UA:     "deadbeef",
		AMR:    []string{"pwd", "totp"},
		Groups: []string{"ops"},
	}

	raw, err := key.SealSession(want)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	got, err := key.OpenSession(raw, now, Bind{Net: "203.0.113.0/24", UA: "deadbeef"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if got.Sub != want.Sub || got.SID != want.SID || len(got.AMR) != 2 {
		t.Fatalf("payload did not survive: %+v", got)
	}
}

/*
 * Главное свойство запечатанного токена: наружу из него не видно ничего.
 * Подписанный отдавал логин и группы любому, кто взглянет на cookie, -- ради
 * этого схема и менялась.
 */
func TestSessionHidesIdentity(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")

	raw, err := key.SealSession(&Session{
		SID: "abc", Sub: "ivanov", Expiry: now.Add(time.Hour).Unix(),
		Groups: []string{"ops", "admins"}, AMR: []string{"pwd", "totp"},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, secret := range []string{"ivanov", "ops", "admins", "totp", "sid"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("token leaks %q in the clear: %s", secret, raw)
		}
	}

	_, body, _ := strings.Cut(raw, ".")

	plain, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("body is not base64url: %v", err)
	}

	for _, secret := range []string{"ivanov", "ops", "admins"} {
		if strings.Contains(string(plain), secret) {
			t.Fatalf("decoded body leaks %q: %q", secret, plain)
		}
	}
}

// Подделка обязана падать на теге, а не на разборе: GCM отдаёт открытый текст
// только после проверки, поэтому чужой JSON не разбирается даже по ошибке.
func TestSessionTampered(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")

	raw, err := key.SealSession(&Session{
		SID: "abc", Sub: "ivanov", Expiry: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	prefix, body, _ := strings.Cut(raw, ".")

	for name, bad := range map[string]string{
		"хвост":               raw + "AA",
		"правленый байт":      prefix + "." + flip(body),
		"билет вместо сессии": "t2." + body,
		"мусор":               "nonsense",
		"пустое тело":         prefix + ".",
	} {
		if _, err := key.OpenSession(bad, now, Bind{}); err == nil {
			t.Fatalf("%s: token was accepted", name)
		}
	}
}

func flip(body string) string {
	b := []byte(body)

	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}

	return string(b)
}

func TestSessionExpiryAndBind(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")

	raw, err := key.SealSession(&Session{
		SID: "abc", Sub: "ivanov",
		Expiry: now.Add(time.Minute).Unix(),
		Net:    "203.0.113.0/24",
		UA:     "deadbeef",
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := key.OpenSession(raw, now.Add(2*time.Minute), Bind{}); err != ErrExpired {
		t.Fatalf("expired token: got %v", err)
	}

	if _, err := key.OpenSession(raw, now, Bind{Net: "198.51.100.0/24"}); err != ErrBind {
		t.Fatalf("foreign subnet: got %v", err)
	}

	if _, err := key.OpenSession(raw, now, Bind{UA: "cafebabe"}); err != ErrBind {
		t.Fatalf("foreign ua: got %v", err)
	}
}

// Чужой ключ -- чужие токены. Та же граница, что отделяет калитку от челленджа
// и капчи, и та же, что отделяет ключ сессии от ключа удостоверения.
func TestForeignKey(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")
	other := mustKey(t, "fedcba9876543210fedcba9876543210")

	raw, err := key.SealSession(&Session{SID: "abc", Expiry: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := other.OpenSession(raw, now, Bind{}); err != ErrSealed {
		t.Fatalf("foreign key: got %v", err)
	}
}

// Область разделена AAD: тем же ключом билет не открывается как сессия.
func TestDomainSeparation(t *testing.T) {
	key := mustKey(t, "0123456789abcdef0123456789abcdef")

	ticket, err := key.SealTicket(&Ticket{
		Nonce: "n1", Scope: "default", Expiry: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := key.OpenSession(ticket, now, Bind{}); err == nil {
		t.Fatal("a ticket opened as a session")
	}

	id, err := key.SealIdentity(&Identity{Sub: "ivanov", Expiry: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := key.OpenTicket(id, now); err == nil {
		t.Fatal("an identity opened as a ticket")
	}

	got, err := key.OpenIdentity(id, now)
	if err != nil || got.Sub != "ivanov" {
		t.Fatalf("identity round trip: %v %+v", err, got)
	}
}

func TestSubnet(t *testing.T) {
	cases := map[string]string{
		"203.0.113.42":        "203.0.113.0/24",
		"2001:db8::1":         "2001:db8::/64",
		"::ffff:203.0.113.42": "203.0.113.0/24",
		"not-an-address":      "",
	}

	for in, want := range cases {
		if got := Subnet(in, 24, 64); got != want {
			t.Fatalf("Subnet(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNeedsRenew(t *testing.T) {
	if (&Session{Renew: 0}).NeedsRenew(now) {
		t.Fatal("renew_after: 0 must disable renewal")
	}

	if !(&Session{Renew: now.Add(-time.Second).Unix()}).NeedsRenew(now) {
		t.Fatal("past renew point must ask for renewal")
	}
}

func TestNewKeyRejectsShort(t *testing.T) {
	if _, err := NewKey([]byte("short\n")); err == nil {
		t.Fatal("a short secret was accepted")
	}

	// Секрет из файла приходит с переводом строки, и он не часть секрета:
	// иначе ключ зависел бы от того, чем файл дописали.
	a := mustKey(t, "  0123456789abcdef0123456789abcdef \n")
	b := mustKey(t, "0123456789abcdef0123456789abcdef")

	raw, err := a.SealSession(&Session{SID: "x", Expiry: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := b.OpenSession(raw, now, Bind{}); err != nil {
		t.Fatalf("trimmed secret produced another key: %v", err)
	}
}
