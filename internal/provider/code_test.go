package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/otp"
)

// Секрет из RFC 6238: ASCII "12345678901234567890" в base32.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// Векторы RFC 6238 для HMAC-SHA1. Совпадение с ними -- единственное
// доказательство, что коды сойдутся с любым аутентификатором, а не только
// сами с собой.
func TestTOTPMatchesRFC6238(t *testing.T) {
	cases := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}

	for at, want := range cases {
		got, err := otp.Code(rfcSecret, time.Unix(at, 0), 30*time.Second, 8)
		if err != nil {
			t.Fatalf("otp.Code(%d): %v", at, err)
		}

		if got != want {
			t.Fatalf("otp.Code(%d) = %s, want %s", at, got, want)
		}
	}
}

func codeProvider(kind string, at time.Time) *Code {
	return &Code{
		Users: map[string]*config.User{
			"ivanov":   {Login: "ivanov", TOTP: rfcSecret},
			"nosecret": {Login: "nosecret"},
		},
		Cfg: &config.CodeProvider{
			Kind:   kind,
			Digits: 6,
			Period: config.Duration(30 * time.Second),
			Skew:   1,
			Codes: []string{
				"$2a$12$SMWBrvxLC2rBY9pNJ4CLnuEpfgTg63XlN16a8Wn59AseYuLNXR4V6",
			},
		},
		Now: func() time.Time { return at },
	}
}

func TestTOTPSkewWindow(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	p := codeProvider(config.CodeTOTP, at)

	// Часы телефона расходятся с сервером всегда: соседний шаг обязан
	// приниматься, а следующий за ним -- нет.
	for _, shift := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		code, err := otp.Code(rfcSecret, at.Add(shift), 30*time.Second, 6)
		if err != nil {
			t.Fatalf("code: %v", err)
		}

		id := &Identity{Subject: "ivanov", AMR: []string{"pwd"}}

		if _, err := p.Verify(context.Background(), Credentials{Code: code}, id); err != nil {
			t.Fatalf("shift %s rejected: %v", shift, err)
		}
	}

	far, err := otp.Code(rfcSecret, at.Add(5*time.Minute), 30*time.Second, 6)
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	id := &Identity{Subject: "ivanov"}

	if _, err := p.Verify(context.Background(), Credentials{Code: far}, id); err == nil {
		t.Fatal("a code five minutes away was accepted")
	}
}

/*
 * Секрета нет -- значит второй фактор этому пользователю не заведён. Пускать
 * без фактора, которого нет, означает, что фактора нет ни у кого.
 */
func TestTOTPWithoutSecretIsNotAllowed(t *testing.T) {
	p := codeProvider(config.CodeTOTP, time.Unix(1_700_000_000, 0))

	_, err := p.Verify(context.Background(), Credentials{Code: "123456"},
		&Identity{Subject: "nosecret"})

	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}

	// Нет личности -- первая калитка не пройдена; код не проверяется вовсе.
	if _, err := p.Verify(context.Background(), Credentials{Code: "123456"},
		nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed without identity", err)
	}
}

func TestStaticCode(t *testing.T) {
	p := codeProvider(config.CodeStatic, time.Unix(1_700_000_000, 0))

	id, err := p.Verify(context.Background(), Credentials{Code: "let-me-in-2fa"}, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Личности за общим кодом нет, и субъект это отражает.
	if id.Subject != "code" || len(id.AMR) != 1 || id.AMR[0] != "code" {
		t.Fatalf("identity %+v", id)
	}

	if _, err := p.Verify(context.Background(), Credentials{Code: "wrong"}, nil); err == nil {
		t.Fatal("a wrong code was accepted")
	}
}

func TestLocalRejectsUnknownAndDisabled(t *testing.T) {
	const hash = "$2a$12$RfCieXmylFauGSITCrA8L.Fx32uDoODW.7bsi4lG6eSIh5taEOzu6"

	off := false
	l := &Local{Users: map[string]*config.User{
		"ivanov":  {Login: "ivanov", Password: hash, Groups: []string{"ops"}},
		"retired": {Login: "retired", Password: hash, Enabled: &off},
	}}

	id, err := l.Verify(context.Background(),
		Credentials{Login: "Ivanov", Password: "waf-demo-2fa"}, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if id.Subject != "ivanov" || len(id.Groups) != 1 {
		t.Fatalf("identity %+v", id)
	}

	if _, err := l.Verify(context.Background(),
		Credentials{Login: "ivanov", Password: "wrong"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("a wrong password was accepted")
	}

	if _, err := l.Verify(context.Background(),
		Credentials{Login: "nobody", Password: "waf-demo-2fa"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("an unknown login was accepted")
	}

	if _, err := l.Verify(context.Background(),
		Credentials{Login: "retired", Password: "waf-demo-2fa"},
		nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatal("a disabled account was let in")
	}

	// Пустой пароль -- частый способ проскочить: bcrypt пустую строку с
	// хешем не сводит, но проверка обязана быть явной.
	if _, err := l.Verify(context.Background(),
		Credentials{Login: "ivanov"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("an empty password was accepted")
	}
}

/*
 * Стыкованная калитка: личность приходит от первой, TOTP добавляет свой
 * фактор к её AMR -- приложение видит pwd+totp.
 */
func TestStackedTOTPKeepsPriorAMR(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	p := codeProvider(config.CodeTOTP, at)

	code, err := otp.Code(rfcSecret, at, 30*time.Second, 6)
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	id, err := Run(context.Background(), p, Credentials{Code: code},
		&Identity{Subject: "ivanov", Groups: []string{"ops"}, AMR: []string{"pwd"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(id.AMR) != 2 || id.AMR[0] != "pwd" || id.AMR[1] != "totp" || id.Subject != "ivanov" {
		t.Fatalf("identity %+v", id)
	}

	if _, err := Run(context.Background(), p, Credentials{Code: "000000"},
		&Identity{Subject: "ivanov"}); err == nil {
		t.Fatal("a wrong code passed")
	}
}

func TestFields(t *testing.T) {
	if f := (&Local{}).Fields(); len(f) != 2 || f[0] != FieldLogin || f[1] != FieldPassword {
		t.Fatalf("local fields %v", f)
	}

	if f := (&Code{}).Fields(); len(f) != 1 || f[0] != FieldCode {
		t.Fatalf("code fields %v", f)
	}
}
