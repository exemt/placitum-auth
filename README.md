# Placitum auth

English · [Русский](README.ru.md)

A login gate in front of an application. The application keeps checking its own users; Placitum
adds one more check, the one the administrator chose in the profile: a one-time code, a list of
logins and passwords, LDAP, NTLM, a token from another issuer, or the application's own login. For
users it is a second factor, for the application a plain header with the name of the signed-in
user.

The nginx module knows nothing about the second factor: to it this is an ordinary inspector that
answers `allow`, `redirect` or `deny`.

## Two processes, one image

| | Inspector (`auth`) | Login form (`auth-http`) |
| --- | --- | --- |
| Where | bus, `waf.req.auth`, queue group | nginx location of the form, `proxy_pass` |
| Called on | every request of the route | sign-in, sign-out and renewal only |
| Budget | about 20 ms | hundreds of milliseconds: bcrypt, LDAP, domain controller |
| Answer | verdict: `allow`, `redirect`, `deny` | form HTML, `Set-Cookie`, 303 back |
| State | token check, dataset mirror in memory | Redis: nonces, attempts |
| When it fails | the route's `waf_deadline` policy | no new sessions; existing ones keep working |

Checking a password must be slow by design, so it cannot live in a process with a 20 ms budget for
all traffic of the route. The third binary, `auth-probe`, is the inspector health check.

## Decision

```
waf_sid opens, not expired, binding matches, session still in the list
                                          → allow + headers for the application
no token or it is not accepted,
    method in redirect_methods and a navigation  → redirect 303 to login.uri
    otherwise                                    → deny response=auth_required (401)
```

A redirect to the login page makes sense only where a person sees the answer in a browser. `POST`,
`PATCH`, `DELETE` and any `fetch` lose the body on 303, so they get 401 with a machine-readable body,
and the client decides whether to show a form. On its own `login.uri` the gate answers `allow`
(`AUTH_SELF`), so the form never requires a sign-in.

## Providers

One profile, one provider. Combinations such as "password plus TOTP" are two gates on the route; the
TOTP gate takes the identity from the session of the first one (`identity.from`).

| Provider | What it proves | Where it is checked |
| --- | --- | --- |
| `local` | a password from a dataset of the space | bcrypt in the form process |
| `code` | a TOTP secret (after another gate) or a shared access code | HMAC, locally |
| `ldap` | a password in a directory | bind to LDAP: `upn`, `dn_template` or `search` |
| `ntlm` | a password in a Windows domain | NTLM bind to the domain controller over LDAP |
| `jwt` | a token issued by someone else, in a cookie or a header | signature and claims, no form |
| `app` | the application's own login | the gate watches the application accept a login and trusts its cookie |

Users of `local` are an ordinary dataset of `login:bcrypt[:groups[:TOTP secret reference]]` lines,
edited like any other dataset, including an expiry per record. Service passwords and TOTP secrets
are references to stored objects (`password_store`) that the form process opens with the
installation key; `password_env` takes the password from an environment variable instead, and a
profile cannot have both.

## Session

```
waf_sid = "s3." + base64url(nonce || AES-256-GCM(payload))
```

The token is sealed, not signed: neither the client nor a proxy log sees the login or the groups.
The payload carries the session id, subject, issue time, expiry, renewal point, issuing source, a
binding to the client subnet (`/24` for IPv4, `/64` for IPv6) and the User-Agent fingerprint, the
passed factors and the groups. A profile accepts tokens only from its own source.

**Cookie and list.** The cookie proves that the session was issued here; a record in an active
dataset proves that it has not been ended. On every request older than the grace window the
inspector checks the session id against its mirror of the dataset: a record means `allow`, no record
means `deny` with `AUTH_SESSION_REVOKED` (the form for navigations), an unavailable list means
`error` with `AUTH_LIST_UNAVAILABLE`. Removing the record is the only way to end a session from
outside: sign-out on the form, the panel and an incident script all do the same thing. The record
carries the login in its reason (`AUTH_LOGIN operator`), so the dataset reads as a list of signed-in
users.

**Renewal.** The module sets no cookie on `allow`, so there is no sliding expiry. After
`renew_after` the inspector redirects a navigation to `<login>/renew`, and the form reissues the
token without asking for the password; `renew_after: 0` turns this off. Renewal is not endless:
`session.max_ttl` is the longest a session lives from sign-in, renewals included (`0` — no limit),
and the form refuses to renew a `local` user who was removed, disabled or given a new password.

**Attempts.** The login ticket is single-use, and failures are counted in Redis both by address and
by login; too many in the window lock sign-in for a while. The attempt is counted before the
password is checked, so parallel submits get no extra guesses; IPv6 addresses are counted by /64.
The address lock is shared by every profile of the process. Password checks running at once are
bounded by `WAF_AUTH_VERIFY_LIMIT`.

## Headers for the application

On `allow` the inspector sets request headers: `X-WAF-User` (the subject), `X-WAF-Groups` (groups,
comma-separated) and `X-WAF-Auth` (passed factors, for example `ldap+totp`). The names are set in
the `upstream` section of the profile. The headers are set every time, even empty: the module cannot
unset request headers, so overwriting is the only way to neutralize an `X-WAF-User` sent by the
client. On routes without the gate the application must not trust these headers; clear them in
nginx:

```nginx
proxy_set_header X-WAF-User "";
```

The application can also read the identity itself from the `waf_id` cookie, sealed with a separate
application key (`WAF_AUTH_APP_KEY_FILE`). The installation key is never given to the application:
with it the application could issue itself a session past the second factor. Neighbouring
inspectors receive the identity through the `sessions` section of later messages, not through
headers.

## Good to know

- **The route must capture headers without masking `cookie`**, otherwise the inspector sees a sha256
  instead of the token and sends signed-in users back to the form.
- **Put gates on separate waves**, in the order `challenge` → `captcha` → `auth`: two redirects on
  one wave race each other.
- **`auth` gives no score.** It decides, it does not evaluate.

Installation, keys and nginx routes are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
