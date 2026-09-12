/*
 * Одноразовый пароль по времени, RFC 6238.
 *
 * Отдельный пакет, а не функция в provider: тот же код нужен пробе, а тянуть
 * ради шести цифр bcrypt и клиент LDAP в диагностическую утилиту незачем.
 *
 * SHA-1 здесь не выбор, а совместимость: аутентификаторы считают именно так, и
 * другой алгоритм означал бы, что коды не сходятся ни с одним приложением.
 */

package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
)

const (
	DefaultStep   = 30 * time.Second
	DefaultDigits = 6
)

// Secret разбирает base32 в том виде, в каком его показывают людям: с
// пробелами, дефисами, в любом регистре и без набивки.
func Secret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))

	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
}

// Code -- код для секрета и момента.
func Code(secret string, at time.Time, step time.Duration, digits int) (string, error) {
	key, err := Secret(secret)
	if err != nil {
		return "", err
	}

	return At(key, counter(at, step), norm(digits)), nil
}

// Counter -- номер шага для момента. Нужен снаружи, чтобы обойти окно skew, не
// пересчитывая деление в каждом вызывающем.
func Counter(at time.Time, step time.Duration) int64 {
	return counter(at, step)
}

func counter(at time.Time, step time.Duration) int64 {
	if step <= 0 {
		step = DefaultStep
	}

	return at.Unix() / int64(step/time.Second)
}

func norm(digits int) int {
	if digits <= 0 {
		return DefaultDigits
	}

	return digits
}

// At -- HOTP из RFC 4226 на готовом ключе и счётчике.
func At(key []byte, counter int64, digits int) string {
	var buf [8]byte

	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for range digits {
		mod *= 10
	}

	out := make([]byte, digits)
	rest := value % mod

	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + rest%10)
		rest /= 10
	}

	return string(out)
}
