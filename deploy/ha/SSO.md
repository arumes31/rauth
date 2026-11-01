# Cross-domain SSO (opt-in SQL authority)

This stage adds browser handoff. It does not enable HA routing, install workers,
or prove database quorum/fencing. Keep production SSO off until the complete
fleet, exact NPM routes and outage acceptance are ready.

## Configuration and identity

Use the same image, keyring, SERVER_SECRET and configuration on every auth node.
SQL authority and its guarded offline cutover are prerequisites (AUTHSTATE.md).
Set, for example:

```
AUTH_STATE_MODE=postgres
SSO_CANONICAL_ORIGIN=https://auth.example.com
SSO_APPLICATION_ORIGINS=https://app.other.test,https://second.example.net
COOKIE_DOMAIN=example.com
WEBAUTHN_ORIGINS=https://auth.example.com
```

Examples contain no live hosts or secrets. Retain the established COOKIE_DOMAIN
(first value is the WebAuthn RP ID) and registered passkey origins. Do not change
RP identity to an application domain or re-enroll existing passkeys. Startup
requires the canonical origin to be covered by that RP and the existing allowed
origins. Application origins are exact HTTPS DNS origins on port 443: no wildcard,
userinfo, path, query, trailing dot or explicit port. Enroll aliases individually.
The opt-in allowlist does not inherit ALLOWED_HOSTS or Public Access wildcards.

SSO uses schema migration 0008. Drain all older SQL-authorizing versions before
enabling it: earlier binaries do not enforce application audiences. Do not run a
mixed-version fleet or roll back to an audience-unaware release while SSO sessions
exist. This is separate from, and subsequent to, the initial SQL authority cutover.
A rollback must stop SSO routes, revoke the affected SQL families, and retain an
SSO-compatible binary/security authority. Never restore old Redis authorizations.

## Browser flow and revocation

1. On the application origin, /_rauth/start creates a five-minute transaction with
   a random 256-bit browser binding in a Secure, HttpOnly, SameSite=Lax __Host
   cookie. Per-transaction names support concurrent tabs. The local return URI
   is validated and encrypted in SQL, preserving opaque paths/query strings.
2. The browser visits /_rauth/authorize on the canonical login origin. Existing
   login, account generation and device/country binding must be valid. Otherwise
   the existing password/TOTP/recovery/passkey flow retains the local authorize
   return URI. Any compatible node can finish the flow.
3. Authorization issues a one-use code valid for at most 60 seconds, bound to
   the destination and common session family. Transaction/browser/code indexes
   are purpose-separated keyed hashes; sensitive payloads use a distinct AEAD
   domain. Raw tokens or codes are not stored as plaintext.
4. /_rauth/callback on the exact application validates its __Host browser binding
   and atomically consumes the code and issues a host-only __Host-rauth-session
   cookie. A missing/wrong browser, different host, replay, expired code or
   revoked/changed account cannot issue a session. Failed insertion does not
   consume a valid code. Redirect immediately to the saved local URI.
5. The app token has an authoritative audience, preserved across rotation and
   replacement. /rauthvalidate accepts it only for the exact trusted forwarded
   application host. It cannot authorize another site, canonical profile/admin,
   passkey enrollment, or a new SSO grant, even if copied/renamed. A broad central
   cookie does not authorize enrolled applications directly.
6. GET /_rauth/logout on an app renders a same-origin confirmation form with
   the global middleware CSRF token. GET never revokes a session. Its POST, or
   canonical logout, revokes the common family,
   including other domains and rotation aliases. Clearing unrelated browser
   cookies is unnecessary for revocation. Credential generation changes also
   invalidate outstanding codes; retaining the caller never revives old codes.

With SSO enabled, the canonical cookie is Secure/HttpOnly/Path=/ and named
__Host-rauth-auth. It has no Domain attribute. SSO reads only this full name and
never falls back to X-rauth-authtoken, which a sibling could plant using a broad
Domain attribute. Cookie writes clear the older COOKIE_DOMAIN-scoped name before
setting the prefixed successor. Enabling SSO therefore requires a fresh canonical
login; combine this with the already planned SQL authority re-login window.
[Browser cookie-prefix rules](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)

Pending login and WebAuthn ceremony cookies retain their existing host scope;
WebAuthn RP identity stays unchanged. With SSO disabled, legacy cookie behavior
and existing integrations remain unchanged. All nodes must agree on the mode.

## Proxy integration gates

The canonical auth host must serve login/profile/WebAuthn/authorize routes on each
frontend without recursive auth_request. Admin routes still go to the control
service; worker-role enforcement and routing are a later stage.

Reserve and collision-check /_rauth/start, /_rauth/callback and /_rauth/logout on
every enrolled application. Proxy these exact paths to the local worker without
its own auth_request; do not exempt an unrestricted path prefix or forward
arbitrary application paths to the auth service. Keep existing Basic Auth, ACLs,
TLS, native application challenges, backend routes and upload behavior intact.
/_rauth/authorize is only served at the canonical origin. Do not add auth self
routes to broad Public Access rules as a recursion workaround.

Overwrite Host with the actual enrolled $host, derive/overwrite original client
IP from the verified socket/proxy chain, and list only the NPM peer in
TRUSTED_PROXIES. Do not use a client-controlled forwarded host to choose an SSO
origin. Serve the application over HTTPS with a matching certificate. All
advertised frontends need the identical exact site routes and a reachable backend.

For a forward-auth validation subrequest, send the original $host and untouched
$request_uri through AUTH_BYPASS_HOST_HEADER / AUTH_BYPASS_URI_HEADER. Preserve
all refresh Set-Cookie values and leave upstream error interception off so an
application-native WebDAV 401 is not turned into an SSO redirect. An auth_request
401 uses the local SSO start flow. Prefer a named proxy error location that sets
X-RAuth-Return-URI to the untouched $request_uri and rewrites to /_rauth/start
without query arguments. Overwrite/clear that header in every reserved route.
This preserves ampersands and percent escapes without constructing a nested
query string. An explicit rd query value must instead be URL-encoded; never
concatenate an unescaped URI into a query. The NPM integration stage must prove
round-trip preservation with ampersands, percent escapes and opaque WebDAV names.

For start/authorize/callback, disable query-bearing proxy access/error logging
and response caching. Code, state and transaction values must not appear in NPM
logs, tracing or analytics. RAuth redacts those query keys (and nested rd), sends
no-store/no-referrer, and keeps query strings out of its request feed. The feed
observes /rauthvalidate decisions only; it does not read NPM logs. The callback
must redirect immediately and must not serve third-party content or assets.
GET /_rauth/logout must be proxied too: its confirmation form supplies the CSRF
token for browsers/clients without Fetch Metadata. POST logout uses the normal
CSRF and cross-origin protection; do not exempt it.

## Validation performed / still required

Real PostgreSQL tests cover two independent stores, atomic concurrent redemption,
wrong state/browser/destination, replay, expiry, insertion rollback, rotation,
credential change/restamp and family-wide logout. HTTP handler tests use password
on one handler and TOTP on another, finish SSO on both unrelated domains, reject
copied cookies, preserve an opaque WebDAV return URI, and verify global logout.
Cookie flags, host-only rotation, exact enrollment, reserved paths and sensitive
log query redaction have regression coverage.

Two actual server processes passed a forced-origin HTTP API fixture with verified
TLS SQL connections and Redis unavailable. Password issuer termination before
TOTP and code issuer termination before callback both succeeded. Per-origin cookie
jars verified audience isolation, cross-process rotation/grace and global logout;
all process logs omitted the generated codes/transaction IDs. The fixture uses
loopback worker transport and is not real-browser or NPM acceptance.

Before rollout, also test independent processes through actual NPM routes with
trusted source headers, real-browser cookie/CSRF/passkey behavior, forced origin
routing, all target host aliases, logout races and HA leader/outage drills.
Unit/handler success is not production or active-active acceptance.
