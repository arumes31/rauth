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

Issue locks the same auth_generations row as current credential changes. Families share revocation and absolute expiry across rotation/replacement and future SSO sessions. Reads join current account/generation and enforce both expiries. Rotation takes generation/family/session locks in that order; retired grace tokens return before acquiring a family lock, and live operations encountering a locked family return explicit ErrBusy so an adapter can retain/retry the current token instead of reporting expiry. Revoke cannot leave a concurrently committed successor active. Refresh writes at most once per 30 seconds (or quarter of a shorter idle lifetime) and cannot extend a retired token or absolute deadline. Authorization reads and single-statement refreshes have a three-second cancellation deadline; multi-statement mutations have a ten-second budget, and startup key validation has a separate fifteen-second budget. All use PostgreSQL time. Parallel full-suite traffic through the remote SSH test tunnel exposed that the earlier uniform three-second mutation budget was too small for its multiple round trips; reads retain the short deadline.

Still required before this store can be selected: session/grant facade and runtime call-site migration; remaining atomic cross-state operations; configuration and key provisioning; startup/readiness separation; real two-process/race/load/failover testing; coordinated cutover that deliberately expires legacy transient state. No active-active acceptance claim follows from this foundation alone.


Cleanup uses independent batches of at most 1,000 rows with one fixed database
cutoff and a separate short deadline per batch. Expired idle rows and children
of absolute-expired families are removed before deleting empty expired families,
so cascade work cannot turn one family batch into an unbounded delete. A later
failure preserves progress from already committed batches. Runtime adapter tests
must preserve ErrBusy semantics in rotation and step-up replacement paths.


## SQL one-use proofs and security counters

The additive 0005 schema and typed artifact/counter stores now cover pending
password-plus-2FA proofs, enrollment proofs and stable temporary TOTP secrets,
passkey ceremonies, invitations, global fixed-window throttles and TOTP replay
markers. Payloads are encrypted with purpose/token authenticated binding; their
IDs and replay/counter keys are keyed digests. Pending proofs bind the original
account generation. Challenges have bounded TTL/payload limits and consumed
proofs cannot be restored. Secret slots alone may be replaced after expiry.

Consume supplies its bounded transaction context to every callback statement.
Enrollment claims the parent proof, writes an eligible account factor and retires
its temporary secret in one transaction. Invitation redemption creates the
account and consumes its proof together; account conflicts roll both back.
Cancellation rolls back the claim and releases locks. Fixed-window counters and
TOTP markers are atomic across independent pools, use database time, and have
bounded cleanup.

Core and handler facades now route these paths through one selected authority;
SQL-focused tests set all Redis clients to nil. Legacy development retains its
raw challenge format with atomically paired ownership metadata. Registration
uses a fresh browser nonce and a session-bound proof, preventing another browser
from consuming it or a credential reset from reusing old step-up. Passkey login
claims its challenge atomically. Production still uses legacy authority and no
SQL mode is exposed until session/grant/startup migration is complete.

Validation includes cross-node one-use races, stale-generation and ciphertext
checks, stable enrollment handoff, invitation/account rollback and redemption
races, shared throttle/replay races, callback cancellation, and browser-bound
registration regressions. CodeRabbit's included review found the callback-context
gap; it was fixed and tested without paid review usage. The full regression
identified one stale username-keyed passkey fixture; it now exercises the new
nonce cookie and authenticated browser context while retaining its deletion and
replay assertions. That test and the other WebAuthn/registration regressions pass.


## Session administration, step-up and revocation reachability

The additive 0006 schema now supplies a keyed optional IP lookup index, token-bound
Public Access grants and stable keyed token-to-family revocation aliases. Family
listing uses bounded keyset pages and returns display-only fields plus a family
handle; it never returns bearer tokens or rotation successors. Owned family
revocation, revoke-others, active IP/family queries and non-reviving country
updates are implemented in the SQL store. Runtime/UI adapters remain to be wired.

Step-up replaces the old token and commits its grant atomically with the exact
owner/generation that supplied the proof. Non-admin, stale-generation and token
collision failures roll back the replacement. Expiry is capped by the session
and family deadlines. Normal rotation preserves an existing grant's original
deadline, while a retired token cannot use it. Credential changes and family
revocation invalidate grants immediately on the next authoritative read.

A racing logout must still reach its family after step-up deletes the old token
or cleanup removes an expired rotation-grace row. Stable keyed revocation aliases
retain that link until absolute family expiry. Cleanup prunes aliases in bounded
batches before deleting empty families, avoiding an unbounded cascade. New
session issuance cannot reuse an outstanding alias within another live family.

The IP digest is a throttle optimization, not a new authentication condition.
Missing or unparseable historical metadata remains issuable/rotatable with a
NULL index and cannot gain an active-IP shortcut. HTTP source trust and existing
binding checks remain separate. This preserves the original contract rather than
stranding sessions on a derived-index error.

Validation: the full SQL authority suite passed (319 seconds), covering the
existing session/artifact/counter tests plus new ownership/pagination, grants,
rotation deadlines, country/expiry and deterministic/racing logout regressions.
Five unparseable-IP cases passed after the review fix. Final vet and lint pass.
CodeRabbit's included review found the optional-index compatibility issues; both
were fixed and tested. Two scanner warnings on challenge-purpose enum strings
were false positives and now carry explicit credential-free justifications.


## Primary application adapters

Primary session reads (root, forward-auth, own-page middleware and SSE
revalidation), issue/rotate/replace/refresh/restamp, logout, binding revocation,
active-IP shortcuts and physical sweeps now route through the selected session
authority. SQL errors never authorize from a Redis fallback. Boolean identity
fields retain the legacy 0/1 representation, and authoritative owner/generation
fields cannot be overridden by payload metadata.

Public Access unlock now replaces the session and creates its grant through one
operation in both adapters. The legacy adapter uses one Lua transaction and
preserves original session expiry; owner/generation mismatches and token
collisions fail without elevation. Unlock checks its owner, and lock errors are
explicit. A credential-change sweep does not bump SQL generation twice.

Real SQL tests run these facades with every Redis client nil, including token
rotation, grant lock, binding invalidation and surviving-session restamp. A
separate test supplies forged valid Redis state while the selected SQL pool is
closed and proves there is no fallback. The complete local suite passed after
this integration; static checks pass and the included CodeRabbit review had no
findings.

Still pending: admin/profile session listing and handle-based revocation,
explicit backend-error HTTP behavior, full runtime selection/key provisioning,
Redis-independent startup/readiness and maintenance, cross-node HTTP/SSO and
coordinated cutover. No production SQL selector is exposed by these adapters.
