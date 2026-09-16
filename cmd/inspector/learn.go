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

func (h *handler) requestHeaders(ctx context.Context, req *protocol.Request) (
	[]protocol.Header, string) {

	if req.RequestStore == nil {
		return nil, ""
	}

	pairs, why, _ := store.Headers(ctx, h.store, req.RequestStore.Headers)

	return pairs, why
}

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
