package learn

import (
	"errors"
	"testing"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/protocol"
)

func hdr(name, value string) protocol.Header { return protocol.Header{name, value} }

func TestMatches(t *testing.T) {
	r := config.AppRoute{URI: "/api/login", Method: "POST"}

	if !Matches(r, "post", "/api/login") {
		t.Fatal("same path and method must match")
	}

	if Matches(r, "GET", "/api/login") || Matches(r, "POST", "/api/login/reset") ||
		Matches(config.AppRoute{}, "POST", "/api/login") {
		t.Fatal("other method, longer path or empty rule must not match")
	}
}

// Set-Cookie: значение без атрибутов, последний побеждает, удаление -- не
// выдача.
func TestIssued(t *testing.T) {
	headers := []protocol.Header{
		hdr("Content-Type", "text/html"),
		hdr("Set-Cookie", "other=1; Path=/"),
		hdr("Set-Cookie", `JSESSIONID="abc"; Path=/; HttpOnly`),
		hdr("set-cookie", "JSESSIONID=def; Max-Age=3600; Secure"),
	}

	if v, ok := Issued(headers, "JSESSIONID"); !ok || v != "def" {
		t.Fatalf("issued: %q %v", v, ok)
	}

	if _, ok := Issued(headers, "missing"); ok {
		t.Fatal("absent cookie reported as issued")
	}

	deleted := []protocol.Header{hdr("Set-Cookie", "JSESSIONID=; Max-Age=0")}
	if _, ok := Issued(deleted, "JSESSIONID"); ok {
		t.Fatal("deletion reported as issued")
	}

	expired := []protocol.Header{hdr("Set-Cookie", "JSESSIONID=x; Max-Age=-1")}
	if _, ok := Issued(expired, "JSESSIONID"); ok {
		t.Fatal("negative max-age reported as issued")
	}
}

func TestExtract(t *testing.T) {
	cases := []struct {
		name string
		f    config.AppField
		body []byte
		args string
		want string
		err  error
	}{
		{"form", config.AppField{From: config.FieldBodyForm, Field: "username"},
			[]byte("username=alice%40x&password=hunter2"), "", "alice@x", nil},
		{"form missing", config.AppField{From: config.FieldBodyForm, Field: "login"},
			[]byte("username=alice"), "", "", ErrNoField},
		{"json", config.AppField{From: config.FieldBodyJSON, Field: "user.email"},
			[]byte(`{"user":{"email":"bob@x","password":"p"}}`), "", "bob@x", nil},
		{"json number", config.AppField{From: config.FieldBodyJSON, Field: "id"},
			[]byte(`{"id": 42}`), "", "42", nil},
		{"json bad", config.AppField{From: config.FieldBodyJSON, Field: "id"},
			[]byte(`{`), "", "", ErrBadBody},
		{"json missing", config.AppField{From: config.FieldBodyJSON, Field: "a.b"},
			[]byte(`{"a":[1]}`), "", "", ErrNoField},
		{"no body", config.AppField{From: config.FieldBodyForm, Field: "u"},
			nil, "", "", ErrNoContent},
		{"args", config.AppField{From: config.FieldArgs, Field: "login"},
			nil, "login=carol&x=1", "carol", nil},
	}

	for _, c := range cases {
		got, err := Extract(c.f, c.body, c.args, nil)

		if !errors.Is(err, c.err) || got != c.want {
			t.Fatalf("%s: got %q err %v, want %q err %v", c.name, got, err, c.want, c.err)
		}
	}

	got, err := Extract(config.AppField{From: config.FieldHeader, Field: "x-user"}, nil, "",
		[]protocol.Header{hdr("X-User", " dave ")})
	if err != nil || got != "dave" {
		t.Fatalf("header: %q %v", got, err)
	}
}

func TestSucceeded(t *testing.T) {
	no := false

	base := config.AppSuccess{Status: []int{200, 302}}

	if !Succeeded(base, 200, nil, true) || !Succeeded(base, 302, nil, true) {
		t.Fatal("listed status with a new cookie must succeed")
	}

	if Succeeded(base, 401, nil, true) {
		t.Fatal("unlisted status must fail")
	}

	// cookie_new по умолчанию: та же кука, что пришла, -- не вход.
	if Succeeded(base, 200, nil, false) {
		t.Fatal("old cookie must fail by default")
	}

	relaxed := config.AppSuccess{Status: []int{200}, CookieNew: &no}
	if !Succeeded(relaxed, 200, nil, false) {
		t.Fatal("cookie_new: false must accept the old cookie")
	}

	withJSON := config.AppSuccess{Status: []int{200},
		JSON: &config.AppJSONCheck{Path: "ok", Equals: "true"}}

	if !Succeeded(withJSON, 200, []byte(`{"ok":true}`), true) {
		t.Fatal("matching json must succeed")
	}

	if Succeeded(withJSON, 200, []byte(`{"ok":false}`), true) ||
		Succeeded(withJSON, 200, nil, true) ||
		Succeeded(withJSON, 200, []byte(`nope`), true) {
		t.Fatal("json mismatch, absent or broken body must fail")
	}
}

func TestReason(t *testing.T) {
	if UserOf(Reason("alice")) != "alice" {
		t.Fatalf("round trip: %q", UserOf(Reason("alice")))
	}

	if UserOf("manual entry") != "" || UserOf("") != "" {
		t.Fatal("foreign reason must not yield a login")
	}

	if Hash("abc") != Hash("abc") || Hash("abc") == Hash("abd") || Hash("abc")[:7] != "sha256:" {
		t.Fatalf("hash: %q", Hash("abc"))
	}
}
