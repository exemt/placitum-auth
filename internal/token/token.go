package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	sessionPrefix  = "s3"
	ticketPrefix   = "t2"
	identityPrefix = "i1"

	keyLabel = "waf-auth aead v2"

	minSecret = 16
)

var (
	ErrMalformed = errors.New("token is malformed")
	ErrSealed    = errors.New("token does not open with this key")
	ErrExpired   = errors.New("token has expired")
	ErrBind      = errors.New("token binding does not match")
)

type Session struct {
	SID    string   `json:"sid"`
	Sub    string   `json:"sub"`
	Issued int64    `json:"iat"`
	Expiry int64    `json:"exp"`
	Renew  int64    `json:"rnw,omitempty"`
	Born   int64    `json:"brn,omitempty"`
	Cred   string   `json:"crd,omitempty"`
	Scope  string   `json:"scp"`
	Iss    string   `json:"iss"`
	Net    string   `json:"net,omitempty"`
	UA     string   `json:"ua,omitempty"`
	AMR    []string `json:"amr,omitempty"`
	Groups []string `json:"grp,omitempty"`
}

type Ticket struct {
	Nonce  string `json:"n"`
	Return string `json:"rd"`
	Scope  string `json:"scp"`
	Expiry int64  `json:"exp"`
}

type Identity struct {
	Sub     string   `json:"sub"`
	Display string   `json:"name,omitempty"`
	Groups  []string `json:"grp,omitempty"`
	AMR     []string `json:"amr,omitempty"`
	Issued  int64    `json:"iat"`
	Expiry  int64    `json:"exp"`
	SID     string   `json:"sid"`
	Scope   string   `json:"scp"`
}

type Bind struct {
	Net string
	UA  string
}

type Key struct {
	gcm cipher.AEAD
}

func NewKey(raw []byte) (*Key, error) {
	secret := strings.TrimSpace(string(raw))
	if len(secret) < minSecret {
		return nil, fmt.Errorf("key must be at least %d bytes, got %d",
			minSecret, len(secret))
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(keyLabel))

	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Key{gcm: gcm}, nil
}

func (k *Key) seal(prefix string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, k.gcm.NonceSize(),
		k.gcm.NonceSize()+len(body)+k.gcm.Overhead())

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := k.gcm.Seal(nonce, nonce, body, []byte(prefix))

	return prefix + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (k *Key) open(prefix, raw string, out any) error {
	kind, body, ok := strings.Cut(raw, ".")
	if !ok || kind != prefix || body == "" {
		return ErrMalformed
	}

	sealed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return ErrMalformed
	}

	if len(sealed) < k.gcm.NonceSize()+k.gcm.Overhead() {
		return ErrMalformed
	}

	nonce := sealed[:k.gcm.NonceSize()]

	plain, err := k.gcm.Open(nil, nonce, sealed[k.gcm.NonceSize():], []byte(prefix))
	if err != nil {
		return ErrSealed
	}

	if err := json.Unmarshal(plain, out); err != nil {
		return ErrMalformed
	}

	return nil
}

func (k *Key) SealSession(s *Session) (string, error) {
	return k.seal(sessionPrefix, s)
}

func (k *Key) SealTicket(t *Ticket) (string, error) {
	return k.seal(ticketPrefix, t)
}

func (k *Key) SealIdentity(id *Identity) (string, error) {
	return k.seal(identityPrefix, id)
}

func (k *Key) OpenSession(raw string, now time.Time, want Bind) (*Session, error) {
	var s Session

	if err := k.open(sessionPrefix, raw, &s); err != nil {
		return nil, err
	}

	if s.SID == "" || s.Expiry == 0 {
		return nil, ErrMalformed
	}

	if now.Unix() >= s.Expiry {
		return &s, ErrExpired
	}

	if want.Net != "" && s.Net != "" && want.Net != s.Net {
		return &s, ErrBind
	}

	if want.UA != "" && s.UA != "" && want.UA != s.UA {
		return &s, ErrBind
	}

	return &s, nil
}

func (k *Key) OpenTicket(raw string, now time.Time) (*Ticket, error) {
	var t Ticket

	if err := k.open(ticketPrefix, raw, &t); err != nil {
		return nil, err
	}

	if t.Nonce == "" || t.Expiry == 0 {
		return nil, ErrMalformed
	}

	if now.Unix() >= t.Expiry {
		return &t, ErrExpired
	}

	return &t, nil
}

func (k *Key) OpenIdentity(raw string, now time.Time) (*Identity, error) {
	var id Identity

	if err := k.open(identityPrefix, raw, &id); err != nil {
		return nil, err
	}

	if id.Expiry != 0 && now.Unix() >= id.Expiry {
		return &id, ErrExpired
	}

	return &id, nil
}

func (s *Session) NeedsRenew(now time.Time) bool {
	return s != nil && s.Renew != 0 && now.Unix() >= s.Renew
}

func NewID() string {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand is unavailable: " + err.Error())
	}

	return hex.EncodeToString(b[:])
}

func Subnet(ip string, v4bits, v6bits int) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}

	addr = addr.Unmap()

	bits := v6bits
	if addr.Is4() {
		bits = v4bits
	}

	if bits <= 0 || bits > addr.BitLen() {
		bits = addr.BitLen()
	}

	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}

	return prefix.String()
}

// NoUA stands for a request without User-Agent: a session bound to a browser
// must not open for a client that sends no header at all.
const NoUA = "none"

func Fingerprint(ua string) string {
	if ua == "" {
		return NoUA
	}

	sum := sha256.Sum256([]byte(ua))

	return hex.EncodeToString(sum[:4])
}

// Credential is a short fingerprint of a stored password hash: a renewed session
// carries it, so a changed password ends the session at the next renewal.
func Credential(hash string) string {
	if hash == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(hash))

	return hex.EncodeToString(sum[:6])
}
