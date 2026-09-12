/*
 * Фаза ответа: подглядывание входа приложения (провайдер app).
 *
 * Калитка здесь ничего не решает -- ответ ушёл бы клиенту при любом
 * вердикте, а редирект на фазе ответа запрещён контрактом. Она смотрит: это
 * маршрут входа, приложение ответило успехом и выдало куку -- значит, с этого
 * момента кука доверенная, и её хеш с логином ложится в активный список.
 * Дальше запросы с этой кукой на обычных маршрутах открываются по списку.
 *
 * Пароль отсюда не выходит: из тела формы достаётся одно поле, названное
 * правилом, и в лог оно попадает только логином.
 */

package main

import (
	"context"
	"time"

	"github.com/exemt/placitum-auth/internal/audit"
	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/decide"
	"github.com/exemt/placitum-auth/internal/learn"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/store"
)

func (h *handler) observe(ctx context.Context, req *protocol.Request) (
	*protocol.Reply, audit.Details) {

	start := time.Now()

	snap := h.profiles.Current()
	profile, _ := snap.Profile(req.Route.Profile)

	/*
	 * Остальным профилям на фазе ответа делать нечего. Отказ, а не тихий
	 * allow: инспектор в наборе фазы ответа у них -- ошибка конфигурации.
	 */
	if profile == nil || profile.Src == nil || !profile.Src.Learns() {
		reply := protocol.NewReply(req, protocol.VerdictDeny)
		reply.Reason = &protocol.Reason{Code: decide.CodeWrongPhase}

		return reply, audit.Details{}
	}

	src := profile.Src
	app := src.Providers.App

	engine := map[string]any{"profile": profile.Name, "phase": req.Phase}

	reply := protocol.NewReply(req, protocol.VerdictAllow)
	reply.Reason = &protocol.Reason{Code: decide.CodeOK}

	done := func(step string) (*protocol.Reply, audit.Details) {
		engine["learn"] = step

		return reply, audit.Details{
			EngineMS: float64(time.Since(start).Microseconds()) / 1000,
			Engine:   engine,
		}
	}

	status := 0
	if req.Response != nil {
		status = req.Response.Status
	}

	/*
	 * Выход: доверие снимается по куке запроса, если приложение ответило
	 * успехом. Запись, которой нет, keeper и так не найдёт.
	 */
	if learn.Matches(app.Learn.Logout, req.HTTP.Method, req.HTTP.URI) {
		pairs, _ := h.requestHeaders(ctx, req)
		cookie := store.Cookie(pairs, app.Cookie)

		if cookie == "" || status < 200 || status >= 400 {
			return done("logout_skipped")
		}

		if err := h.lists.Remove(src.List.Sessions, learn.Hash(cookie),
			"AUTH_LOGOUT"); err != nil {
			h.log.Warn("session list remove failed", "rid", req.RID,
				"source", src.Name, "error", err.Error())
			engine["error"] = err.Error()

			return done("logout_list_error")
		}

		return done("logout")
	}

	if !learn.Matches(app.Learn.Login, req.HTTP.Method, req.HTTP.URI) {
		return done("skip")
	}

	issued, ok := learn.Issued(h.responseHeaders(ctx, req), app.Cookie)
	if !ok {
		return done("no_cookie")
	}

	reqPairs, why := h.requestHeaders(ctx, req)
	if why != "" {
		engine["store"] = why
	}

	requested := store.Cookie(reqPairs, app.Cookie)

	var (
		body []byte
		args string
	)

	switch app.Learn.User.From {
	case config.FieldBodyForm, config.FieldBodyJSON:
		var bwhy string

		body, bwhy = h.requestBody(ctx, req)
		if bwhy != "" {
			/*
			 * Тела не видно -- учить нечему. Чаще всего это маршрут входа без
			 * waf_capture request body: сказать об этом надо громко, иначе
			 * калитка молча не пускает никого.
			 */
			engine["body"] = bwhy
			h.log.Warn("login body unavailable, nothing learned", "rid", req.RID,
				"source", src.Name, "uri", req.HTTP.URI, "why", bwhy)

			return done("no_body")
		}

	case config.FieldArgs:
		if req.RequestStore != nil {
			args = store.Args(ctx, h.store, req.RequestStore.Args)
		}
	}

	user, err := learn.Extract(app.Learn.User, body, args, reqPairs)
	if err != nil {
		engine["error"] = err.Error()

		return done("no_user")
	}

	engine["sub"] = user

	var respBody []byte

	if app.Learn.Success.JSON != nil {
		respBody, _ = store.Body(ctx, h.store, req.Store.Body)
	}

	if !learn.Succeeded(app.Learn.Success, status, respBody, issued != requested) {
		engine["status"] = status

		return done("rejected")
	}

	id := learn.Hash(issued)
	ttl := src.List.TTL.D()
	now := time.Now()

	if err := h.lists.Add(src.List.Sessions, id, ttl, learn.Reason(user)); err != nil {
		h.log.Warn("session list add failed", "rid", req.RID, "source", src.Name,
			"sub", user, "error", err.Error())
		engine["error"] = err.Error()

		return done("list_error")
	}

	engine["sid"] = id

	reply.Sessions = []protocol.Session{{
		Source:   src.Name,
		Kind:     protocol.SessionApp,
		User:     user,
		ID:       id,
		Verified: true,
		Issued:   now.Unix(),
		Expires:  now.Add(ttl).Unix(),
	}}

	h.log.Info("application login learned", "rid", req.RID, "source", src.Name,
		"sub", user, "sid", id, "ttl", ttl.String())

	return done("ok")
}

// requestHeaders -- заголовки фазы запроса: на фазе ответа они лежат в
// request_store. Второе значение -- причина, по которой их нет.
func (h *handler) requestHeaders(ctx context.Context, req *protocol.Request) (
	[]protocol.Header, string) {

	if req.RequestStore == nil {
		return nil, ""
	}

	pairs, why, _ := store.Headers(ctx, h.store, req.RequestStore.Headers)

	return pairs, why
}

/*
 * responseHeaders -- заголовки ответа: со снимком они лежат в обменнике (и
 * к ним применены маски маршрута), без снимка модуль присылает их инлайном,
 * но без set-cookie -- маскировать его нечем. Значит, без
 * waf_capture response headers на маршруте входа подглядывание не работает,
 * и это видно по шагу no_cookie.
 */
func (h *handler) responseHeaders(ctx context.Context, req *protocol.Request) []protocol.Header {
	if req.Store.Headers != nil && req.Store.Headers.Placed() {
		pairs, _, _ := store.Headers(ctx, h.store, req.Store.Headers)

		return pairs
	}

	if req.Response != nil {
		return req.Response.Headers
	}

	return nil
}

func (h *handler) requestBody(ctx context.Context, req *protocol.Request) ([]byte, string) {
	if req.RequestStore == nil {
		return nil, store.UnavailableNotFound
	}

	body, why := store.Body(ctx, h.store, req.RequestStore.Body)
	if why == "" && body == nil {
		return nil, store.UnavailableNotFound
	}

	return body, why
}
