# Installation

English · [Русский](INSTALL.ru.md)

One image, two containers: the inspector on the bus and the HTTP login form. Usually
`placitum-core` installs them; this page lists what they need, how the settings are named and which
nginx routes must exist.

```sh
docker build -f deploy/Dockerfile -t placitum/auth .
```

The image contains `auth`, `auth-http`, `auth-probe`, the login page `web/` and a single disabled
profile `default`. Real profiles come from the controller as generations; until then the gate is
declared but silent.

| Service | Command | Role |
| --- | --- | --- |
| `inspector-auth` | `auth` | subscribes to `waf.req.auth` and answers within about 20 ms |
| `auth-http` | `auth-http` | the login form, the target of `waf_redirect_allow` |

They scale independently: the inspector grows with the route's request rate, the form with the
number of sign-ins.

## Settings

| Variable | Read by | Default | Purpose |
| --- | --- | --- | --- |
| `NATS_URL` | both | `nats://127.0.0.1:4222` | bus; the form needs it only for `list.sessions` |
| `WAF_AUTH_SUBJECT` | inspector | `waf.req.auth` | subscription |
| `WAF_AUTH_NAME` | both | `auth` | name in the inspector registry |
| `WAF_AUTH_PROFILES` | both | `./profiles`; `/app/profiles` in the image | bootstrap profiles |
| `WAF_AUTH_DATA` | both | empty; `/var/lib/waf/auth` in the image | applied generation from the controller; empty means bootstrap profiles only |
| `WAF_AUTH_KEY_FILE` | both | — | required: the key that seals sessions and form tickets |
| `WAF_AUTH_APP_KEY_FILE` | form | empty | application identity key; without it `waf_id` is not issued |
| `WAF_AUTH_HTTP_URL` | inspector | empty | address of the form process |
| `WAF_AUTH_LISTEN` | form | `:8080` | form address |
| `WAF_AUTH_WEB` | form | `./web`; `/app/web` in the image | page template directory |
| `WAF_AUTH_CONTROLLER` | form | empty | controller address for stored object envelopes |
| `WAF_AUTH_SCOPE` | form | empty | space UUID or `name:<name>` |
| `WAF_AUTH_CONTOUR_KEY` | form | empty | private installation key that opens `store:` references |
| `WAF_AUTH_COOKIE_SECURE` | form | `on` | cookies over TLS only; set `off` while the node serves plain HTTP |
| `WAF_AUTH_REAL_IP_HEADER` | form | `X-Forwarded-For` | client address header; the last value is used, the one the node appended |
| `WAF_AUTH_VERIFY_LIMIT` | form | CPU count, at least 2 | password checks running at once; a submit that waits longer than 5 s for its turn is refused |
| `REDIS_URL` | inspector | `url` from `inspector.conf` | buffer: request headers with the session cookie |
| `REDIS_INTERNAL_URL` | form | `internal` from `inspector.conf` | internal Redis for nonces, attempts and the session mirror; falls back to `REDIS_URL` with a warning |
| `WAF_AUTH_GEO_ADDR` | inspector | empty | network directory (`host:port`) for dataset writes with `write: net`, `net_all` or `asn`; empty makes them answer `AUTH_GEO_UNAVAILABLE` |
| `WAF_AUTH_GEO_TIMEOUT`, `WAF_AUTH_GEO_NEG_MAX` | inspector | `500ms`, `0` | network directory wait on a miss and negative cache limit |
| `WAF_AUTH_STORE_TIMEOUT` | inspector | `150ms` | buffer read timeout |
| `WAF_AUTH_WORKERS`, `WAF_AUTH_QUEUE_DEPTH`, `WAF_AUTH_QUEUE_FULL`, `WAF_AUTH_QUEUE_EXPAND` | inspector | CPUs, `inspector.conf` | workers and queue |
| `WAF_AUTH_VERSIONS` | inspector | `2` | accepted message schema versions |
| `WAF_AUTH_LOG` | both | `info` | log level |

LDAP service passwords come either from a stored object (`password_store`) or from an environment
variable named in the profile (`password_env`).

## Keys

There are two keys, and that is not duplication. The installation key seals the session and the
form ticket; only the inspector and the form know it. The application key seals the `waf_id`
identity; the protected application knows it too. The keys are not generated at start, because two
replicas would issue incompatible tokens: without the file the process does not start.

```sh
openssl rand -hex 32 > secrets/auth.hmac
openssl rand -hex 32 > secrets/auth-app.hmac
```

## nginx routes

```nginx
waf_inspector auth subject=waf.req.auth;
waf_deny_response auth_required status=401;
waf_redirect_allow /waf/login;

server {
    location / {
        waf_capture request headers;
        waf_inspect request auth wave=2 timeout=20ms;
        proxy_pass http://app;
    }

    location /waf/login {
        proxy_pass http://auth_http;
    }
}
```

The form path must match `login.uri` of the profile and be listed in `waf_redirect_allow`. The gate
answers `allow` on its own `login.uri`, so the form location may keep the server's inspectors. If
the form container is recreated more often than nginx reloads, address it through a variable and a
`resolver` instead of an `upstream` block.

## Checking

The image has a `HEALTHCHECK`: `auth-probe` publishes an inspection and waits for a verdict. For
`auth-http` override it with an HTTP check of the form.

## Pitfalls

- **`WAF_AUTH_COOKIE_SECURE` is `on` by default.** Behind plain HTTP the browser never returns the
  cookie, and every sign-in ends on the form again.
- **Emergency exit.** If sign-in breaks, remove `auth` from `waf_inspect` of the route: an inspector
  that is not selected is not asked, and no redirects happen.
