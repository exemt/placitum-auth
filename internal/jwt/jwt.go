package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

var (
	ErrMalformed = errors.New("jwt: malformed token")
	ErrAlg       = errors.New("jwt: algorithm mismatch")
	ErrSignature = errors.New("jwt: signature does not verify")
	ErrKey       = errors.New("jwt: key does not fit the algorithm")
)

type Token struct {
	Header map[string]any
	Claims map[string]any

	raw       string
	signing   string
	signature []byte
}

func Parse(raw string) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}

	t := &Token{
		raw:       raw,
		signing:   parts[0] + "." + parts[1],
		signature: sig,
	}

	if err := json.Unmarshal(head, &t.Header); err != nil || t.Header == nil {
		return nil, ErrMalformed
	}

	if err := json.Unmarshal(body, &t.Claims); err != nil || t.Claims == nil {
		return nil, ErrMalformed
	}

	return t, nil
}

func (t *Token) Alg() string {
	alg, _ := t.Header["alg"].(string)

	return alg
}

func (t *Token) Verify(alg string, key []byte) error {
	if t.Alg() != alg {
		return fmt.Errorf("%w: token says %q, source expects %q", ErrAlg, t.Alg(), alg)
	}

	hash, ok := hashOf(alg)
	if !ok {
		return fmt.Errorf("%w: unsupported %q", ErrAlg, alg)
	}

	switch alg[:2] {
	case "HS":
		mac := hmac.New(hash.New, key)
		mac.Write([]byte(t.signing))

		if !hmac.Equal(mac.Sum(nil), t.signature) {
			return ErrSignature
		}

		return nil

	case "RS":
		pub, err := publicKey(key)
		if err != nil {
			return err
		}

		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an RSA public key", ErrKey, alg)
		}

		if err := rsa.VerifyPKCS1v15(rsaKey, hash, digest(hash, t.signing),
			t.signature); err != nil {
			return ErrSignature
		}

		return nil

	case "ES":
		pub, err := publicKey(key)
		if err != nil {
			return err
		}

		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an EC public key", ErrKey, alg)
		}

		n := (ecKey.Params().BitSize + 7) / 8
		if len(t.signature) != 2*n {
			return ErrSignature
		}

		r := new(big.Int).SetBytes(t.signature[:n])
		s := new(big.Int).SetBytes(t.signature[n:])

		if !ecdsa.Verify(ecKey, digest(hash, t.signing), r, s) {
			return ErrSignature
		}

		return nil
	}

	return fmt.Errorf("%w: unsupported %q", ErrAlg, alg)
}

func (t *Token) Hash() string {
	sum := sha256.Sum256([]byte(t.raw))

	return "sha256:" + hex.EncodeToString(sum[:])
}

func (t *Token) claim(name string) (any, bool) {
	if name == "" {
		return nil, false
	}

	if v, ok := t.Claims[name]; ok {
		return v, true
	}

	if !strings.Contains(name, ".") {
		return nil, false
	}

	var cur any = t.Claims

	for _, part := range strings.Split(name, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}

		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}

	return cur, true
}

func (t *Token) String(name string) string {
	v, _ := t.claim(name)

	switch v := v.(type) {
	case string:
		return v

	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)

	case json.Number:
		return v.String()

	case bool:
		return strconv.FormatBool(v)
	}

	return ""
}

func (t *Token) Strings(name string) []string {
	v, _ := t.claim(name)

	switch v := v.(type) {
	case []any:
		out := make([]string, 0, len(v))

		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}

		return out

	case string:
		fields := strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ' '
		})

		if len(fields) == 0 {
			return nil
		}

		return fields
	}

	return nil
}

func (t *Token) Int(name string) (int64, bool) {
	v, _ := t.claim(name)

	switch v := v.(type) {
	case float64:
		return int64(v), true

	case json.Number:
		n, err := v.Int64()

		return n, err == nil

	case string:
		n, err := strconv.ParseInt(v, 10, 64)

		return n, err == nil
	}

	return 0, false
}

func hashOf(alg string) (crypto.Hash, bool) {
	switch alg {
	case "HS256", "RS256", "ES256":
		return crypto.SHA256, true

	case "HS384", "RS384", "ES384":
		return crypto.SHA384, true

	case "HS512", "RS512":
		return crypto.SHA512, true
	}

	return 0, false
}

func digest(hash crypto.Hash, input string) []byte {
	switch hash {
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(input))

		return sum[:]

	case crypto.SHA512:
		sum := sha512.Sum512([]byte(input))

		return sum[:]
	}

	sum := sha256.Sum256([]byte(input))

	return sum[:]
}

func publicKey(raw []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: key_file is not PEM", ErrKey)
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)

	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)

	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		return cert.PublicKey, nil
	}

	return nil, fmt.Errorf("%w: unexpected PEM block %q", ErrKey, block.Type)
}
