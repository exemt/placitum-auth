/*
 * Токены калитки: сессия (waf_sid), билет формы (waf_lgn) и удостоверение для
 * приложения (waf_id).
 *
 * Все три запечатанные, а не подписанные, и разница существенная: подписанный
 * токен любой желающий читает глазами, а внутри сессии лежат логин, группы и
 * список пройденных факторов. Показать приложению, кто вошёл, и тем же
 * значением показать это клиенту и всякому, кто увидит cookie, -- разные вещи,
 * и вторая не нужна.
 *
 * AES-256-GCM: подделать нельзя ровно так же, как подписанный (тег -- тот же
 * MAC), а прочитать нельзя вовсе. Ключ шифрования выводится из секрета контура
 * HMAC-ом с меткой: сам секрет произвольной длины, а AES-256 хочет ровно
 * тридцать два байта.
 *
 * Форма одна на все три: <prefix>.<base64url(nonce || ciphertext)>. Префикс он
 * же AAD -- билетом формы нельзя притвориться сессией, даже имея тот же ключ.
 */

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
	// Версия формы. Растёт, когда меняется набор полей или сама схема: старый
	// токен с новым разбором обязан быть отвергнут, а не понят приблизительно.
	// s3 добавил iss -- имя источника входа; сессии s2 без него принимать
	// нельзя, их пространство определялось только именем куки.
	sessionPrefix  = "s3"
	ticketPrefix   = "t2"
	identityPrefix = "i1"

	// Метка вывода ключа. Общая на все три вида токена, поэтому меняется только
	// вместе со сменой криптосхемы: рост версии одного вида отсекается его
	// префиксом (он же AAD), а смена метки обесценила бы заодно и удостоверения
	// приложений, чью схему никто не трогал.
	keyLabel = "waf-auth aead v2"

	// Ключ выводится хешем, но короткий секрет остаётся коротким секретом.
	minSecret = 16
)

var (
	ErrMalformed = errors.New("token is malformed")
	ErrSealed    = errors.New("token does not open with this key")
	ErrExpired   = errors.New("token has expired")
	ErrBind      = errors.New("token binding does not match")
)

/*
 * Session -- то, что доказывает вход. Имена полей короткие: токен едет в
 * каждом запросе клиента, и лишние байты здесь платятся трафиком.
 */
type Session struct {
	SID    string `json:"sid"`
	Sub    string `json:"sub"`
	Issued int64  `json:"iat"`
	Expiry int64  `json:"exp"`
	Renew  int64  `json:"rnw,omitempty"`
	Scope  string `json:"scp"`
	/*
	 * Iss -- имя источника входа, выдавшего сессию. Профиль принимает только
	 * сессии своего источника: совпадение имён кук у двух источников -- ошибка
	 * конфигурации, а не общее пространство, и штамп не даёт ей стать дырой
	 * даже в окно, пока реестр её не отверг.
	 */
	Iss    string   `json:"iss"`
	Net    string   `json:"net,omitempty"`
	UA     string   `json:"ua,omitempty"`
	AMR    []string `json:"amr,omitempty"`
	Groups []string `json:"grp,omitempty"`
}

// Ticket -- задание формы: одноразовый nonce и куда вернуть клиента. Ставит
// его инспектор вердиктом redirect, читает HTTP-процесс.
type Ticket struct {
	Nonce  string `json:"n"`
	Return string `json:"rd"`
	Scope  string `json:"scp"`
	Expiry int64  `json:"exp"`
}

/*
 * Identity -- удостоверение для защищаемого приложения. То же, что заголовки
 * X-WAF-*, но живёт в cookie и потому переживает быстрый путь по активному
 * списку, где инспектора не спрашивают и заголовки ставить некому.
 *
 * Запечатано отдельным ключом: приложение обязано уметь его открыть, а ключ
 * сессии ему давать нельзя -- с ним можно выписать себе вход.
 */
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

// Bind -- то, к чему привязан токен. Пустое поле означает "не проверяем":
// профиль может отключить любую из привязок.
type Bind struct {
	Net string
	UA  string
}

// Key -- ключ контура. Один на инспектор и HTTP-процесс; у удостоверения
// приложения свой, из другого файла.
type Key struct {
	gcm cipher.AEAD
}

// NewKey выводит ключ шифрования из секрета контура.
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

/*
 * seal запечатывает payload. Nonce случайный и едет в открытую перед
 * шифротекстом: GCM его не прячет и прятать не должен, а повтор nonce на одном
 * ключе -- единственный способ его сломать, поэтому он из crypto/rand.
 */
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

/*
 * open проверяет тег и расшифровывает. Порядок здесь не выбирают: GCM отдаёт
 * открытый текст только после проверки тега, поэтому разобрать чужой JSON
 * невозможно даже по ошибке.
 */
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

/*
 * OpenSession -- горячий путь инспектора. Ошибка любой из проверок означает
 * одно и то же: сессии нет. Различаются они только кодом в аудите, потому что
 * "не открылся" и "срок вышел" -- разные события для оператора и одинаковые
 * для клиента.
 */
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

// OpenIdentity нужен пробе и тестам: в контуре удостоверение открывает
// приложение, а не калитка.
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

// NeedsRenew -- пора ли перевыпустить действующую сессию. Точка продления
// нулевая означает, что продления у профиля нет вовсе.
func (s *Session) NeedsRenew(now time.Time) bool {
	return s != nil && s.Renew != 0 && now.Unix() >= s.Renew
}

// NewID -- 128 бит из crypto/rand: и sid сессии, и nonce формы.
func NewID() string {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand на Linux не отказывает; если отказал, продолжать
		// с предсказуемым идентификатором нельзя.
		panic("auth: crypto/rand is unavailable: " + err.Error())
	}

	return hex.EncodeToString(b[:])
}

/*
 * Subnet -- привязка к подсети, а не к адресу. Мобильные сети меняют адрес в
 * течение сессии, и привязка к /32 означала бы вход заново на каждом переходе
 * между вышками.
 */
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

/*
 * Fingerprint -- отпечаток User-Agent. Хеш, а не строка: в токен уезжает то,
 * что видно в браузере клиента, и полный UA там не нужен ни для чего.
 */
func Fingerprint(ua string) string {
	if ua == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(ua))

	return hex.EncodeToString(sum[:4])
}
