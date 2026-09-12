package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
)

func b64(v any) string {
	raw, _ := json.Marshal(v)

	return base64.RawURLEncoding.EncodeToString(raw)
}

func hs256(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()

	signing := b64(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + b64(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))

	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestHS256RoundTrip(t *testing.T) {
	raw := hs256(t, map[string]any{"sub": "alice", "exp": 1757260800, "groups": []string{"ops", "dev"}}, "s3cret")

	tok, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := tok.Verify("HS256", []byte("s3cret")); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if tok.String("sub") != "alice" {
		t.Fatalf("sub: %q", tok.String("sub"))
	}

	if exp, ok := tok.Int("exp"); !ok || exp != 1757260800 {
		t.Fatalf("exp: %d %v", exp, ok)
	}

	if g := tok.Strings("groups"); len(g) != 2 || g[0] != "ops" || g[1] != "dev" {
		t.Fatalf("groups: %v", g)
	}

	if tok.Hash() == "" || tok.Hash()[:7] != "sha256:" {
		t.Fatalf("hash: %q", tok.Hash())
	}
}

// Чужой секрет -- подпись не сходится; заголовок с другим alg -- подмена
// алгоритма, и до подписи дело не доходит.
func TestHS256Rejects(t *testing.T) {
	raw := hs256(t, map[string]any{"sub": "alice"}, "s3cret")

	tok, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := tok.Verify("HS256", []byte("other")); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}

	if err := tok.Verify("HS512", []byte("s3cret")); !errors.Is(err, ErrAlg) {
		t.Fatalf("alg mismatch: %v", err)
	}

	if err := tok.Verify("RS256", []byte("s3cret")); !errors.Is(err, ErrAlg) {
		t.Fatalf("alg mismatch rs: %v", err)
	}
}

func TestRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signing := b64(map[string]any{"alg": "RS256"}) + "." + b64(map[string]any{"sub": "bob"})
	sum := sha256.Sum256([]byte(signing))

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	raw := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	tok, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := tok.Verify("RS256", pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	derOther, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	pubOther := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derOther})

	if err := tok.Verify("RS256", pubOther); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}

	if err := tok.Verify("RS256", []byte("not pem")); !errors.Is(err, ErrKey) {
		t.Fatalf("not pem: %v", err)
	}
}

func TestES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signing := b64(map[string]any{"alg": "ES256"}) + "." + b64(map[string]any{"sub": "carol"})
	sum := sha256.Sum256([]byte(signing))

	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	// JWS: r||s по 32 байта, не DER.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	raw := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	tok, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := tok.Verify("ES256", pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Испорченная подпись той же длины.
	bad := new(big.Int).Add(r, big.NewInt(1))
	bad.FillBytes(sig[:32])
	rawBad := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	tokBad, _ := Parse(rawBad)
	if err := tokBad.Verify("ES256", pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, raw := range []string{"", "a.b", "a.b.c.d", "!!.!!.!!", b64("x") + ".e30.sig"} {
		if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: %v", raw, err)
		}
	}
}

// Claims разных форм: строка, число, массив, строка через пробел.
func TestClaimShapes(t *testing.T) {
	tok, err := Parse(hs256(t, map[string]any{
		"sub":   12345,
		"scope": "read write",
		"aud":   []string{"api", "web"},
		"iat":   "1757232000",
		"flag":  true,
	}, "k"))
	if err != nil {
		t.Fatal(err)
	}

	if tok.String("sub") != "12345" || tok.String("flag") != "true" || tok.String("nope") != "" {
		t.Fatalf("strings: %q %q", tok.String("sub"), tok.String("flag"))
	}

	if s := tok.Strings("scope"); len(s) != 2 || s[1] != "write" {
		t.Fatalf("scope: %v", s)
	}

	if a := tok.Strings("aud"); len(a) != 2 || a[0] != "api" {
		t.Fatalf("aud: %v", a)
	}

	if iat, ok := tok.Int("iat"); !ok || iat != 1757232000 {
		t.Fatalf("iat: %d %v", iat, ok)
	}

	if _, ok := tok.Int("sub_missing"); ok {
		t.Fatal("missing claim must not be a number")
	}
}

// Путь через точку: личность во вложенном объекте (Juice Shop -- data.email).
// Claim с точкой в самом имени побеждает путь.
func TestClaimPath(t *testing.T) {
	tok, err := Parse(hs256(t, map[string]any{
		"data": map[string]any{"id": 7, "email": "admin@juice-sh.op", "roles": []string{"admin"}},
		"a.b":  "literal",
		"a":    map[string]any{"b": "nested"},
		"nbf":  1,
	}, "k"))
	if err != nil {
		t.Fatal(err)
	}

	if tok.String("data.email") != "admin@juice-sh.op" || tok.String("data.id") != "7" {
		t.Fatalf("path: %q %q", tok.String("data.email"), tok.String("data.id"))
	}

	if r := tok.Strings("data.roles"); len(r) != 1 || r[0] != "admin" {
		t.Fatalf("roles: %v", r)
	}

	if tok.String("a.b") != "literal" || tok.String("data.nope") != "" || tok.String("nbf.x") != "" {
		t.Fatalf("precedence: %q %q", tok.String("a.b"), tok.String("data.nope"))
	}
}
