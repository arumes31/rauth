# Policy worker reconciliation and request ownership

`internal/clusterworker` connects the shared PostgreSQL authority, durable Linux
cache, signature verification, bounded freshness and immutable compiled policy
objects. It is not yet wired to RAuth HTTP routes or the concrete core compiler.
Production remains unchanged; this does not enroll/deploy a worker or activate HA.

## Runtime contract

The caller supplies a verified-TLS authority reader, existing mount-guarded host
cache root, scoped public verifier and private staging compiler factory. Workers
never receive the signing key or policy database write credentials. Every compiler
validates each dependency, checks complete manifest semantics and transfers an
immutable io.Closer value only after Finish succeeds. Close releases untransferred
resources exactly once. No staging callback mutates application globals.

New verifies its active cache, but never restores a lease. A cache older than its
durable watermark remains unready until the authoritative replacement arrives.
Run uses independent head-poll and staging loops. A current signed HA head is
checked every ten seconds with a three-second read deadline. Notify is a bounded,
coalesced hint that triggers another authoritative read, never cached head proof
or a lease renewal. Notification reads are budgeted at one per second.

A verified new head withdraws old admission before disk I/O. Record its durable
watermark before staging. Integrity/rollback/equivocation/persistence failures
invalidate readiness immediately; an unavailable authoritative read can use only
the existing lease. New heads cancel obsolete downloads. Staging/compilation is
bounded at 120 seconds and must honor context cancellation. Commit the complete
cache before publishing its immutable runtime pointer; re-check freshness at that
publication. Failed or delayed activation cannot borrow a previous lease.

WithPolicy pins the exact ready verified generation for the full callback. Use it
around the request handler, place that immutable object in request context, and
use it for every matching, feed and GeoIP decision. Do not retain its resources
after returning or mutate them. Replaced objects close only after all callbacks
finish. Shutdown invalidates readiness immediately and releases the owner
reference; an in-flight callback still owns its object until it returns.

Status separates policy readiness, last head/staging error and disk cleanup health.
Its error causes are private operational data, not public HTTP response content.
Collector health does not participate in admission.

## Remaining application and deployment gates

Implement the core compiler over matching rules, complete feeds, GeoIP and
versioned node-specific security configuration. Integrate WithPolicy at the start
of request processing, before original-IP/country evaluation. Put worker admin
writes behind the authenticated controller relay; implement enrolled private
mTLS APIs and host-mounted secret/mount guards. PostgreSQL strict synchronous HA,
quorum, fencing, verified leader routing, durable events, actual worker networking,
NPM canary, browser/passkey acceptance and outage drills remain required.

Native Linux tests exercise startup/restart, durable watermark behavior, new-head
withdrawal, cancellation during blocked downloads, compiler failure, pinned
resource retirement, integrity/persistence failures, independent polling and
shutdown. An actual verified-TLS PostgreSQL test runs two worker runtimes, restarts
one from cache, updates both and proves one worker's expired head lease denies
requests while another can renew from shared state. This is one database, not a
quorum/failover test. Windows explicitly skips Linux cache-backed checks.

Included CodeRabbit review completed with one conditional concern: whether
ObserveHead invalidates the lease on rejection. Its implementation already clears
the deadline on every error. An additional ready-worker regression explicitly
checks lower revisions and same-revision equivocation; no duplicate invalidation
or change to lease behavior is required. No paid review was used.

A structurally valid store whose active payload cannot load/compile starts
unready and reports the restore error while retaining its watermark. It can
rehydrate verified content or await a newer compatible policy. This permits a
coordinated configuration/compiler update without making startup depend on an
old policy compiling under the new settings. Invalid roots/journals and invalid
runtime configuration still fail construction; no stale authorization is restored.
