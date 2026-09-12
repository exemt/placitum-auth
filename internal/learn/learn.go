/*
 * Подглядывание входа приложения (провайдер app). Калитка не проверяет
 * пароль -- это делает приложение; она смотрит на фазе ответа маршрута
 * входа, что приложение вход приняло и какую куку выдало, и с этого момента
 * кука доверенная: её хеш ложится в активный список с логином в reason.
 *
 * Пакет чистый: байты тела, заголовки и правило на входе, решение на
 * выходе. Пароль отсюда не выходит никуда -- из тела достаётся ровно одно
 * поле, названное правилом.
 */

package learn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/protocol"
)

var (
	ErrNoField   = errors.New("learn: login field is absent")
	ErrBadBody   = errors.New("learn: body does not parse")
	ErrNoContent = errors.New("learn: request body is not available")
)

// Matches -- этот запрос и есть вход (или выход) приложения: тот же путь и
// метод. Путь сравнивается целиком: /api/login и /api/login/reset -- разные
// вещи, а строка запроса в uri сообщения не едет.
func Matches(r config.AppRoute, method, uri string) bool {
	return r.URI != "" && uri == r.URI && strings.EqualFold(method, r.Method)
}

/*
 * Issued -- значение куки name из заголовков ответа. Set-Cookie с пустым
 * значением или Max-Age=0 -- это удаление, а не выдача. Несколько Set-Cookie
 * с тем же именем -- последний побеждает, как в браузере.
 */
func Issued(headers []protocol.Header, name string) (string, bool) {
	value, found := "", false

	for _, h := range headers {
		if !strings.EqualFold(h.Name(), "set-cookie") {
			continue
		}

		v, ok := setCookie(h.Value(), name)
		if !ok {
			continue
		}

		value, found = v, v != ""
	}

	return value, found
}

func setCookie(line, name string) (string, bool) {
	parts := strings.Split(line, ";")

	key, value, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !ok || strings.TrimSpace(key) != name {
		return "", false
	}

	value = strings.Trim(strings.TrimSpace(value), `"`)

	for _, attr := range parts[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(attr), "=")

		if strings.EqualFold(strings.TrimSpace(k), "max-age") {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n <= 0 {
				return "", true
			}
		}
	}

	return value, true
}

/*
 * Extract достаёт логин из запроса по правилу: поле формы, поле JSON тела
 * (путь через точку), параметр строки запроса либо заголовок. Ничего, кроме
 * названного поля, отсюда не выходит.
 */
func Extract(f config.AppField, body []byte, args string,
	headers []protocol.Header) (string, error) {

	switch f.From {
	case config.FieldBodyForm:
		if body == nil {
			return "", ErrNoContent
		}

		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", ErrBadBody
		}

		return first(values[f.Field])

	case config.FieldBodyJSON:
		if body == nil {
			return "", ErrNoContent
		}

		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", ErrBadBody
		}

		v, ok := lookup(doc, f.Field)
		if !ok {
			return "", ErrNoField
		}

		return scalar(v)

	case config.FieldArgs:
		values, err := url.ParseQuery(args)
		if err != nil {
			return "", ErrBadBody
		}

		return first(values[f.Field])

	case config.FieldHeader:
		for _, h := range headers {
			if strings.EqualFold(h.Name(), f.Field) {
				return strings.TrimSpace(h.Value()), nil
			}
		}

		return "", ErrNoField
	}

	return "", fmt.Errorf("learn: unknown source %q", f.From)
}

func first(values []string) (string, error) {
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", ErrNoField
	}

	return strings.TrimSpace(values[0]), nil
}

// lookup ходит по пути через точку внутри разобранного JSON. Индексов
// массивов нет: логин лежит в объекте, а не в списке.
func lookup(doc any, path string) (any, bool) {
	cur := doc

	for _, part := range strings.Split(path, ".") {
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

func scalar(v any) (string, error) {
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return "", ErrNoField
		}

		return strings.TrimSpace(x), nil

	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil

	case bool:
		return strconv.FormatBool(x), nil
	}

	return "", ErrNoField
}

/*
 * Succeeded -- приняло ли приложение вход. Все предикаты правила обязаны
 * сойтись: статус из списка, новая кука (если требуется) и поле JSON ответа
 * (если задано). body -- тело ответа, нужно только при json; nil при
 * заданном json -- проверка не прошла, а не пропущена.
 */
func Succeeded(s config.AppSuccess, status int, body []byte, cookieNew bool) bool {
	okStatus := false

	for _, code := range s.Status {
		if code == status {
			okStatus = true
			break
		}
	}

	if !okStatus {
		return false
	}

	if s.RequiresCookieNew() && !cookieNew {
		return false
	}

	if s.JSON != nil {
		if body == nil {
			return false
		}

		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return false
		}

		v, ok := lookup(doc, s.JSON.Path)
		if !ok {
			return false
		}

		got, err := scalar(v)
		if err != nil || got != s.JSON.Equals {
			return false
		}
	}

	return true
}

// Hash -- идентификатор сессии приложения по куке: в список и в аудит едет
// он, а не сама кука, которая и есть учётные данные.
func Hash(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))

	return "sha256:" + hex.EncodeToString(sum[:])
}

/*
 * reason записи списка -- тот же, что у своих сессий формы (AUTH_LOGIN <кто>):
 * панель читает список как список вошедших, а калитка достаёт из него логин.
 */
const reasonPrefix = "AUTH_LOGIN "

func Reason(user string) string { return reasonPrefix + user }

// UserOf -- логин из reason записи; пусто, если запись сделал кто-то другой
// (рука оператора, скрипт) и логина в ней нет.
func UserOf(reason string) string {
	if !strings.HasPrefix(reason, reasonPrefix) {
		return ""
	}

	return strings.TrimSpace(reason[len(reasonPrefix):])
}
