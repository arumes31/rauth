# Two-host application canary

On 2026-11-01, the integrated runtime at revision
96ea68b9253addf73701c52b3da4bf6a8e4d5433 ran as isolated Linux containers on Hodus
(control) and orderotto-dev (worker). Production authentication, NPM routes and
DNS remained unchanged. The canary used its own PostgreSQL database, private
certificate authorities, random authentication keys and test-only .invalid
origins. Its database is a single disposable instance, not the planned HA service.

Both apps run as UID 10001, with read-only root filesystems, dropped capabilities,
explicit host bind mounts and their own existing RAuth Tailscale service network
namespace. SQL requires verify-full TLS, the test SQL CA, a writable endpoint and
SCRAM channel binding. A certificate signed with ECDSA/SHA-256 supports that
binding; the node mTLS identities retain separate Ed25519 keys. Workers receive
no controller signer, source/write credentials or initial account credentials.
The worker's schema check uses its restricted role and performs no DDL.

The immutable main executable SHA-256 for the initial run was
`ec422c9371348bc4a92ba009e541a9bc2ee86ffc280d513b627383af45e29942`.
It was bound read-only into the existing pinned runtime base image. The PR's
separate Docker build and test workflows also passed. This canary layout is a
fixture, not the production deployment manifest.

## Verified behavior

- The actual feed at https://blocklist.eworx.at/api/v1/raw returned 4,773 normalized
  entries for this fetch. Both apps deny a listed source with HTTP 403 and allow
  an unlisted source on Public Access. Valid sessions cannot bypass feed denial.
- Password verification on control followed by 2FA on worker succeeds. A code
  issued on worker is consumed on control. Reusing the SSO callback is rejected.
- Authenticated administration on worker reaches control through actual
  source-bound, pinned mTLS and the current SQL registry. Its response preserves
  the canonical host-only cookie and CSRF flow, including step-up rotation.
- With only the canary control app stopped, worker completes a fresh password,
  2FA and SSO callback. Existing sessions and default-feed denial survive a worker
  restart using its persisted signed cache and fresh SQL head. A consumed pending
  second-factor token cannot issue a second auth cookie. Admin returns 503;
  the observed CLI response took 0.728 seconds. Control was restored afterward.
- A real GeoLite2-Country database (3,403,332 bytes, SHA-256
  `4d3587f2f39e8d5dced147bfcaa2a13b1655938930ed020e25929e91e1303fc8`)
  is captured, signed, transferred and compiled on both nodes. An authenticated
  UI mutation relayed through worker creates a country allow list. Actual US and
  NL database results produce allow/deny responses on both nodes; unknown and
  unselected countries fail closed. Valid sessions retain these restrictions.
  The observed country update converged in 14.038 seconds with polling enabled.
- A new Public Access rule submitted through the UI inherits the managed Eworx
  default. The separate IP Feeds menu and the default entry render for the admin.

## Small resource sample

Fifty sequential country-allowed local HTTP requests per node all returned 200.
Control had 44,080 KiB RSS (50,808 KiB high water), with 0.502 ms median and
0.614 ms p95. Worker had 27,012 KiB RSS (29,388 KiB high water), with 0.259 ms
median and 0.592 ms p95. Each container had a 384 MiB limit and a 3,489,739-byte
persistent signed cache. These measurements include the real country database
and feed. They are host-to-local-bridge samples, excluding public TLS/NPM and
concurrent load; they are not capacity or production latency claims.

The canary exposed a control-source initialization discrepancy: an existing
GeoIP file was re-opened using environment defaults instead of the caller's
already guarded node path. Startup now opens cfg.MaxMindDBPath directly.
Authorization already used the signed snapshot's reader; the correction also
makes control-source lookups and metadata use the configured file.

## Remaining rollout gates

This test stops the control application, not Hodus itself: its SQL database and
TCP transport remain on Hodus. It does not prove SQL leader/quorum failover,
watchdog fencing, partitions, backup/PITR restoration or real host loss. The
three-host infrastructure, durable request-event delivery, remaining NPM workers/routes and canonical auth ingress
still require implementation and acceptance. All public rules must retain their
default feed while existing login protection remains intact. Browser and physical
passkey acceptance are separate from these CLI/API fixtures.


## Policy synchronization canary extension

The 2a81e2963ad3fb76a8e1aefa235cd7683eacd26a runtime now runs on both test
hosts with migration 0011 and the documented source/publisher grants. The clean
AMD64 executable SHA-256 is
`76023485a6cf46387cb1d2e2397af876ff46776c58b0b2b0ec4e62ad4aa7379f`.
A private custom-format database backup was saved before the fixture migration;
older stopped worker binaries cannot restart against schema 11 without a
compatible restore/release. This remains an isolated fixture upgrade.

An authenticated request through worker renders Policy Sync and returns both
nodes' durable confirmations. Stopping the worker before a rule edit keeps the
new source pending. Restarting it applies and confirms the new head. A further
country-policy edit with both nodes healthy reached confirmation and enforcement
on both nodes in 5.219 seconds; the resulting policy revision was 7. The live
Eworx generation at this test contained 4,826 entries.

A direct pinned, source-bound TLS 1.3 connection received the master's first
policy notice in 5 ms. A duplicate stream for the worker identity returned 429,
confirming its runtime stream was already connected and the per-node limit
was enforced. The control-application outage test was repeated on this build:
existing authenticated sessions, new password/2FA/SSO, feed denial and worker
restart passed with control stopped; admin returned 503 in 0.758 seconds.
Control was restored. SQL/proxy and Hodus itself stayed online throughout.

Validation also passed all full affected SQL suites on Windows, all 47 integrated
root groups natively on Linux, five native receipt groups, 18 affected native core
groups and three CLI-only frontend groups. Included review completed with zero
findings; lint and Windows/Linux gosec reported zero issues. Frontend regressions
run in both existing CI test jobs. These are not physical browser/passkey or
three-host infrastructure/fencing acceptance results.
