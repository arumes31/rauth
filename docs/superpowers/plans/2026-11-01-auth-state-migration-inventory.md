# Authentication-state migration inventory

Status: SQL session foundation in source on feat/sql-auth-state. The deployed runtime remains Redis-authoritative. Do not expose a SQL/HA deployment mode until every security path below uses the selected authority. There is no authorization fallback between stores.

## Existing state and required adapters

| State | Current source | Required SQL behavior |
| --- | --- | --- |
| Session issue/rotate/replace/refresh/restamp | core/authgen.go | Atomic family/session operations with account-generation locks; preserve 30-second rotation grace, absolute expiry, bounded refresh writes |
| Validation and binding | handlers/auth.go, middleware/auth.go, handlers/live_feed.go, core/session.go | Authoritative reads on every validation; no stale positive cache; shared geo/device rules; explicit errors |
| Session administration/profile | handlers/admin.go, handlers/profile.go, core/redis.go | Paginated metadata listing and family handles, no raw bearer tokens in admin responses; revoke one family or other families; typed IP-session checks |
| First-factor pending 2FA/setup | handlers/auth.go | Encrypted TTL-bound purpose-specific challenges; single successful consumption, generation binding; do not restore consumed proofs on ambiguous results |
| Temporary TOTP setup secret | handlers/auth.go | Bind encrypted secret to the setup challenge; stable value across node handoff; atomic setup eligibility check and consumption |
| Passkey registration/authentication ceremony | handlers/webauthn.go | Browser/challenge-bound encrypted state; single consumption across nodes; retain RP identity, origin checks and auth generation |
| TOTP replay marker | core/twofactor.go | Globally atomic short-lived marker; consistent normalized code digest, fail closed on errors |
| Recovery codes and passkey/account changes | core/twofactor.go, core/user.go, authgen.go | Already SQL, retain existing transactional generation locks; integrate proof/session transactions where required |
| Admin Public Access step-up grant | handlers/bypass.go | Bound to newly replaced session, current user/generation and expiry; no grant inherited by a token captured before step-up; rotate/replace atomically |
| Invitations | handlers/invite.go | Encrypted purpose-specific token state; atomically create account and consume invite in one transaction; no consume-then-restore race |
| Global security throttles | core/limiter.go | Atomic fixed-window increment/check/reset with shared DB time and bounded retention; fail closed on backend error; retain per-worker flood limits |

Main startup and health still require Redis. ServerSecret is currently initialized by InitRedis; move secret initialization before store selection. ImportFromRedis remains a deliberate durable-data migration, not a session authorization fallback. Background session-index reconciliation and admin SSE revalidation must use the selected store too.

## SQL session foundation

The new internal/authstate package and additive 0004 schema provide a typed session contract and PostgreSQL implementation without enabling it in production. Sessions store an HMAC digest of the bearer token. Session metadata and rotation successors use AES-GCM with a purpose-specific encryption key and authenticated row/token binding. A stable index secret is separate from the rotatable encryption keyring (one active key and up to two retiring keys). Startup compares keyed fingerprints and rejects mismatched index/key-ID material or missing live keys. Decryption selects the recorded key ID exactly; it does not guess keys.

Issue locks the same auth_generations row as current credential changes. Families share revocation and absolute expiry across rotation/replacement and future SSO sessions. Reads join current account/generation and enforce both expiries. Rotation takes generation/family/session locks in that order; losing concurrent rotations skip a locked family instead of waiting behind the winner. Revoke cannot leave a concurrently committed successor active. Refresh writes at most once per 30 seconds (or quarter of a shorter idle lifetime) and cannot extend a retired token or absolute deadline. Authorization reads and single-statement refreshes have a three-second cancellation deadline; multi-statement mutations have a ten-second budget, and startup key validation has a separate fifteen-second budget. All use PostgreSQL time. Parallel full-suite traffic through the remote SSH test tunnel exposed that the earlier uniform three-second mutation budget was too small for its multiple round trips; reads retain the short deadline.

Still required before this store can be selected: Redis development adapter and runtime call-site migration; family listing/revoke-others/IP-session queries; challenge/invite/replay/grant/counter stores; atomic cross-state operations; configuration and key provisioning; startup/readiness separation; real two-process/race/load/failover testing; coordinated cutover that deliberately expires legacy transient state. No active-active acceptance claim follows from this foundation alone.
