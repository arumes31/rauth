# Implementation plan: RAuth public-access policies and active-active authentication

Date: 2026-11-01 (Europe/Vienna)
Status: Approved for implementation by the user goal on 2026-11-01. Work in progress; deployment gates remain mandatory.
Design: ../specs/2026-11-01-public-access-active-active-design.md
Baseline: main 52cd1a2f95a2004c722f6ef572da86859100f491
Documentation branch: docs/public-access-ha-design

The user explicitly requested both design and implementation plan before implementation. This plan is therefore delivered alongside the proposed design. The brainstorming skill's referenced writing-plans helper was not found in the installed skill directories; the plan below follows the repository's existing task/validation format directly.

## Working rules

- Begin implementation only after the design/plan is approved. Approval of documents does not mean failed infrastructure gates have passed.
- Preserve existing required-login rules and all other NPM protections. No automatic fail-open fallback.
- Use isolated branches/worktrees outside Nextcloud for code. Do not modify the user's synced checkout or unrelated changes.
- Proposed new files below are implementation targets, not files already created. Adapt names to repository conventions at implementation time.
- Extend existing interfaces and tests where they already cover the behavior; avoid tests that only mirror implementation.
- Each substantial code batch receives appropriate local review and existing CI. Run CodeRabbit CLI at meaningful milestones within the free quota; on Windows also check %LOCALAPPDATA%\Programs\coderabbit\coderabbit.exe. Respect cooldowns, report unavailable/quota-limited review, and continue manual review/testing.
- Split changes into reviewable PRs. Do not merge a later deployment stage merely because an earlier one is green.
- Keep user/account IDs, passkey RP identity, current WebDAV path behavior and native application authentication intact.
- Never commit secrets, live environment dumps, production databases or feed credentials.

## Dependency sequence

Inventory and benchmarks -> policy model -> feeds -> management UI.
Inventory and benchmarks -> SQL auth-state abstraction -> transactional migration -> cross-node SSO.
Those two tracks -> worker roles/snapshots -> central events -> HA integration/failure tests -> NPM canary -> expanded rollout -> health-aware external routing.

Policy/feed UI work can ship independently in single-node mode after its own checks. Active-active routing cannot ship until shared security state, cross-node flows and HA failure tests pass.

## Task 1: Finish inventory and establish deployment gates

Existing inputs:
- Current source under internal/core, internal/handlers, internal/middleware, main.go and docker-compose.ghcr.yml.
- Prior the control host monitoring verification at the private verified rollout report.
- Read-only discovery in the design: four NPM instances; nine public entries on second state host; worker host C and worker host D need authenticated host-rule inspection.

Actions:
1. Obtain existing authorized management access to worker host C and worker host D; inventory proxy entries, aliases, custom locations, RAuth/login rules, NPM ACLs, Basic Auth, SSL and backend targets.
2. Verify the control host/nl inventory remains current. Record auth/admin self-reference and pure redirect/dead/stream exceptions separately.
3. Measure resources, architecture, storage durability and pairwise latency on candidate state hosts. Confirm three independent failure domains and that no auth routing/DNS/TLS prerequisite relies only on the control host.
4. Identify current external DNS provider/proxy modes, health-routing capabilities and existing entitlement. Do not purchase a service.
5. Measure typical/peak auth request rate, especially WebDAV traffic, and current latency. Obtain representative intended feed URLs without enabling them.
6. Record a per-host backup/restore method and test restores in an isolated environment.

Deliverables:
- Sanitized deployment inventory and compatibility matrix.
- Fixed state-host placement, resource budgets, failure detection settings and measurable routing plan.
- Explicit list of applications whose backend prevents surviving a the control host outage.

Gate: do not schedule production cluster or DNS work while host access, backend equivalence or safe fencing remains unverified.

## Task 2: Introduce the public-policy decision model

Existing targets:
- internal/core/bypass.go and bypass_test.go
- internal/handlers/auth.go, bypass.go and bypass_test.go
- internal/middleware/request_feed.go
- internal/core/migrations (additive migration if required)

Proposed additions: policy.go, policy_test.go and explicit typed policy-decision results.

Actions:
1. Extend rule metadata with country mode/list, private-network choice and attached feed IDs. Old records default to all/no feeds.
2. Separate selecting a rule from deciding whether it allows a request. Keep existing specificity and path normalization.
3. Validate trusted original IP and target once; distinguish missing/invalid identity from unknown geolocation.
4. Apply selected-rule country/feed restrictions before any successful session return. Do not search broader public rules after a conditional rejection.
5. Preserve anonymous identity-header clearing and global login/session geofence checks.
6. Define consistent 2xx/401/403 decisions and operational-error behavior for nginx integration.
7. Add effective-policy evaluation reusable by the admin preview and live requests.

Meaningful verification:
- Table/property tests for host/path precedence, conditional no-fallthrough and logged-in bypass attempts.
- IPv4, IPv6, mapped IPv4, private/Tailscale, unknown-country and forged-header cases.
- Existing semicolon/encoded-percent WebDAV cases and application-native 401 challenge handling.
- Example focused command: go test ./internal/core ./internal/handlers ./internal/middleware -run 'Bypass|Policy|Country|RequestFeed' -count=1 (with the existing test PostgreSQL fixture where needed).

Gate: migrated rules are behaviorally equivalent until an admin explicitly configures restrictions.

## Task 3: Implement feed lifecycle, fetching and local matching

Proposed targets:
- internal/core/ipfeed.go, ipfeed_fetch.go, ipfeed_compile.go and focused tests
- additive ip_feeds/feed_versions metadata and rule-reference schema
- private immutable feed payload storage, outside public static files

Actions:
1. Implement the documented IP/CIDR text parser, normalization, deduplication and bounded compile representation.
2. Implement HTTPS fetching with timeout, decompression/entry limits, certificate validation and SSRF protection across DNS results and redirects.
3. Publish immutable validated generations. Preserve last-good data on all download/validation failures.
4. Require a successful initial fetch before attachment; explicit audited acceptance for legitimate empty/large-drop updates.
5. Schedule refresh with jitter and single-controller ownership; manual refresh uses the same job and limits.
6. Prevent deletion of referenced feeds. Store credential references separately; redact sensitive URLs/errors.
7. Implement atomic policy-plus-feeds activation and monotonic generation checks; a rollback is a newly signed higher revision referencing known good payloads.
8. Benchmark full configured limits and ensure compilation cannot exhaust worker resources.

Tests:
- Valid IPv4/IPv6/CIDRs, duplicate/comment handling, malformed/HTML/oversized/compressed responses.
- Mixed public/private DNS answers, rebinding, redirect-to-metadata/internal endpoints and credential redaction.
- Concurrent refresh, failed updates, corrupt payload/hash/signature, restart and missing referenced feed.
- Benchmark lookup/compile costs using generated fixtures, not live provider downloads in CI.

Gate: no failed update, partial generation or empty accidental response can remove an existing block.

## Task 4: Add Public Access controls and the IP Feeds admin menu

Existing targets:
- internal/handlers/admin.go, admin_view.go and bypass.go
- templates/partials/management/admin_public_access.html, admin_bypass_modal.html, admin_sidebar.html
- templates/management.html, static/js/management.js and console components

Proposed additions: handlers/ipfeeds.go, admin_ip_feeds.html and management/ip-feeds.js.

Actions:
1. Add country mode, searchable checkbox list, selected count, private-network setting and attached-feed controls.
2. Add effective-policy summary and read-only URL/IP test, including the winning rule and reason.
3. Add feed CRUD, refresh/status, usage references and error/stale state.
4. Reuse the current step-up unlock, CSRF, admin checks and audit patterns for security-sensitive mutations.
5. Add worker desired/applied-version status so a saved policy is not presented as fully deployed prematurely.
6. Preserve responsive layouts, accessible labels, safe text rendering and keyboard behavior.

Tests:
- Handler auth/CSRF/step-up and server validation, including forged country/feed IDs.
- UI mobile/desktop checks for country search, stale/error states and large selections.
- Rule list/edit round-trips without hidden field loss.
- CodeRabbit milestone after the policy/feed/UI batch, then targeted fixes and regression checks.

Gate: user can see exactly which URL, country choices and feeds will be effective before saving.

## Task 5: Introduce a transactional authentication-state interface

Existing targets:
- internal/core/redis.go, authgen.go, session.go, twofactor.go, limiter.go
- handlers/auth.go, webauthn.go, invite.go, stepup.go, profile.go, bypass.go
- middleware/auth.go, main.go and health handler

Proposed additions:
- authstate.go interface and typed operations;
- postgres_authstate.go plus additive schemas for sessions, challenges, replay markers, step-up grants, invitations and global security counters.

Actions:
1. Inventory every TokenDB/InviteDB/security RateLimitDB access and define typed operations with explicit atomicity, expiry and idempotency contracts.
2. Keep a legacy adapter during development; HA mode must require the SQL authority. No mixed active authorities or dual-authorizing fallback.
3. Implement atomic session issue/rotate/replace/revoke/refresh with account-generation checks and absolute expiry.
4. Implement single-use challenge/TOTP/invite consumption and transactionally safe recovery/passkey workflows.
5. Use keyed token digests and existing cluster encryption. Add a validated keyring/rotation mechanism without falling back to arbitrary keys.
6. Preserve current session binding and the 30-second rotation grace; make hot-path expiry refresh bounded.
7. Move authentication security throttles to globally consistent counters; retain local flood protection.
8. Remove Redis from mandatory startup/readiness in SQL HA mode. Start workers in a defined degraded state when SQL is down but a valid local public policy exists.
9. Separate auth readiness, policy readiness and event-collector health.

Tests:
- Existing auth, binding, generation, rotation, profile, invite, 2FA, recovery, passkey and CSRF tests through the new adapter.
- Real PostgreSQL concurrency tests: consume twice from two processes; rotate versus logout; password reset versus session issuance; ambiguous commit/retry.
- Full relevant race run and SQL timeout/load tests.
- Search again for direct Redis authority accesses; review every remaining one.

Gate: no security-critical operation depends on an asynchronously replicated Redis write. Keep this PR sequence separate from DNS/production HA activation.

## Task 6: Support cross-node and cross-domain authentication flows

Existing targets: auth/webauthn handlers, config.go, cookie helpers, nginx-proxy-example.conf and redirect validation.

Proposed additions: SSO transaction/code store and handlers, callback endpoints, matching tests.

Actions:
1. Run at least two identical instances against shared test auth state; begin every auth flow on A and complete on B.
2. Preserve canonical auth hostname, cookie compatibility, WebAuthn RP ID and registered origins.
3. Implement exact enrolled-host callback allowlists and browser-bound, short-lived SSO transactions.
4. Atomically redeem a one-use code at the destination; issue a host-only app session linked to a global session family.
5. Apply global logout/revocation to all linked site sessions. Expire or invalidate sessions rather than relying on clearing cookies on unrelated domains.
6. Validate and preserve intended local return paths without open redirects; keep callback query material out of logs and referrers.
7. Ensure the pending-login and session keys used by all nodes are compatible before enabling routing.

Tests:
- Password A / TOTP B / validate C; passkeys and recovery codes across nodes.
- Cross-domain redirect/callback with a central existing login; malicious destination, state mismatch and code replay rejection.
- Global logout, absolute expiry and credential-reset invalidation across domains.
- WebDAV/opaque filename returns and native app-login/public routes.
- Cookie/CSRF behavior on the same hostname with forced origin routing.

Gate: no sticky sessions needed and no domain-cookie assumptions remain undocumented.

## Task 7: Build worker roles, identity and atomic policy synchronization

Existing targets: config.go, main.go, health handler, compose and Docker image configuration.

Proposed additions: worker/control route groups, enrollment identity handling, snapshot loader and private sync protocol.

Actions:
1. Define control and worker roles in the same image. Authentication remains available on both; worker admin mutations are disabled.
2. Enroll per-node mutual-TLS identities; private APIs authorize policy fetch and event submission separately.
3. Stage and verify signed, versioned manifests plus all feed/GeoIP dependencies before activation.
4. Persist active/previous generation and anti-rollback metadata. Restore after restart without contacting the control host.
5. Push change notifications plus periodic reconciliation; expose desired/applied version and stale status.
6. Keep original-IP trust explicit; migrate frontend headers only after spoofing and session-binding tests.
7. Make database endpoint discovery and TLS independent of the control host. No runtime Docker socket mounts.

Tests:
- Invalid/revoked node identity, unauthorized writes, old revision replay, corrupt/incomplete payload, aborted activation and restart.
- the control host offline before/after worker restart, with healthy HA auth state.
- Public degraded-start behavior versus protected-route fail-closed behavior.
- Frontend IP normalization parity.

Gate: a worker cannot activate partial rules, silently open a protected route or depend on the control host for startup of an already configured public policy.

## Task 8: Add durable RAuth event forwarding and central SSE

Existing targets: core/request_feed.go, middleware/request_feed.go, handlers/live_feed.go and static/js/management/live-feed.js.

Proposed additions: local spool, authenticated ingestion handler, central request-event store and node status UI.

Actions:
1. Extend the bounded event schema with worker, timestamps, rule/version and denial reason. Continue excluding sensitive URL/body/header content.
2. Add bounded asynchronous local persistence, stable event IDs and restart recovery.
3. Deliver acknowledged batches to the control host; deduplicate durable inserts. Separate catch-up and live delivery budgets.
4. Add retention/storage caps, drop/gap accounting and spool health. Do not couple auth availability to collector health.
5. Persist central cursors and stream accepted events instantly over existing admin-only SSE.
6. Add node/reason filters and delayed-replay indication while preserving pause/search/mobile behavior.
7. Keep existing security audit retention and ownership rules distinct from request-event retention.

Tests:
- Duplicate delivery, lost ACK, collector outage, restart, disk full, queue overflow, retention expiry and reconnect cursor.
- Auth latency remains bounded during event failures.
- No NPM log readers or volumes; no upstream HTTP status mislabeling.
- Admin SSE revocation and access-control tests continue passing.
- UI renders untrusted URL/worker/feed text safely.

Gate: show measured backlog capacity and explicit gaps; do not claim unlimited lossless buffering.

## Task 9: Create and test the HA deployment

Proposed deliverables:
- deploy/ha/ example Compose/config templates, secret placeholders and runbooks;
- integration fixture for multiple RAuth processes, three PostgreSQL data nodes, etcd quorum, per-node leader routing and event collector;
- no production keys or live domain values committed.

Actions:
1. Pin images and versions; configure strict synchronous PostgreSQL, safe Patroni promotion, three voters and a tested fencing mechanism.
2. Configure local database routing to only the current leader with TLS verification.
3. Add backups, restore/PITR procedures, disk monitoring, certificate/key rotation and time synchronization.
4. Load representative traffic and test the performance/recovery objectives from the design.
5. Simulate loss of the control host, each data leader/follower, a worker, collector and network links.
6. Verify that an isolated former leader cannot keep accepting security writes and that committed revocation/consumption survives the supported single-host failure.
7. Document quorum-loss behavior and operator recovery without data-loss promotion.

Validation:
- Complete existing Go suite and relevant race tests once the implementation is stable.
- Use the repository's normal PostgreSQL test fixture/env; do not assume a production DB.
- Run multi-node failure suite separately from normal unit tests.
- CodeRabbit milestone for the auth-state/worker/SSO batch within quota, plus human-readable review of the state transitions and migration.
- Existing CI/security workflows must be green for the exact release commits.

Gate: do not advertise active-active readiness until the fresh-login/2FA handoff and outage drills pass. A successful container health endpoint alone is insufficient.

## Task 10: Cut over authentication state with a reversible release

Actions:
1. Deploy an additive, migration-capable release and verified backups.
2. Prepare durable credential/config state on the HA cluster; compare account IDs, passkeys, recovery records and policy counts without disclosing secrets.
3. Drain old login mutations for the cutover window. Expire legacy transient sessions, pending flows, invites and step-up grants; communicate the one-time re-login and invite reissue.
4. Switch the enabled fleet to the single SQL authority. Never leave old Redis-authorizing nodes reachable.
5. Exercise fresh login, 2FA, passkey, rotation and revoke on every frontend.
6. Retain only rollback binaries compatible with the new state authority. Do not restore old Redis tokens or pre-revocation snapshots into live authorization.

Gate: confirm new authority and release compatibility before worker/NPM expansion. This is a planned migration interruption, distinct from subsequent automatic single-host failover.

## Task 11: Integrate NPM hosts with a canary and coverage manifest

Actions:
1. Back up each host's source configuration and produce a domain-by-domain diff.
2. Install local worker integration on one currently public low-risk application; attach an exact Public Access rule.
3. Preserve auth requirements, access lists and app-native challenges. Treat canonical auth/admin/validate endpoints as explicit recursion exceptions.
4. Verify IPv4/IPv6/Cloudflare/direct traffic, native 401s, WebSockets, uploads, custom locations, callbacks and percent/semicolon paths.
5. Use supported persistent NPM configuration hooks, validate nginx -t, then reload and compare baseline behavior.
6. Expand host by host, adding exact public aliases and retaining all private rules. Include worker host C compatibility work if preflight requires it.
7. Verify every eligible entry against the coverage manifest; record justified non-app exceptions.

Gate: coverage is verified per actual enabled route, not inferred from having one RAuth container on a server. Rollback is per host/rule and preserves required authentication.

## Task 12: Enable routing and prove the requested outage behavior

Actions:
1. Verify the canonical auth hostname and each candidate application hostname through every intended origin with correct Host/SNI/TLS.
2. Configure health-aware external routing using existing capabilities. Plain round-robin records may distribute traffic but do not satisfy withdrawal/failover acceptance by themselves.
3. Ensure auth readiness checks include the shared state and key/policy compatibility; public-app checks include the local policy and independent backend where appropriate.
4. Disable the control host in a controlled drill while preserving two healthy state voters/data nodes. Perform fresh password + 2FA login, validate an existing session, and open public and protected canaries from another frontend.
5. Confirm central UI unavailability does not stop auth, buffered RAuth events replay with deduplication, and application-backend dependencies are correctly reported.
6. Measure failover, DNS/cache behavior, latency and backlog recovery; restore the control host safely and verify no split brain or automatic stale-policy downgrade.
7. Save sanitized evidence and rollback instructions.

Completion evidence:
- Exact release image digests, CI links and migration result.
- Per-NPM-host integration manifest with preserved private/public modes.
- Cross-node and cross-domain auth test results.
- Country/feed policy test matrix and update-failure behavior.
- Actual the control host-outage and leader-failover results, with measured recovery interval.
- Event backlog/replay/gap behavior and capacity.
- DNS/routing health checks plus documented backend limitations.

## Review and approval checkpoint

The design and this plan are proposed deliverables. Review especially:
- Moving security-critical Redis state into shared HA PostgreSQL.
- Three independent state nodes and fail-closed behavior if quorum is lost.
- Cross-domain SSO callbacks and globally revocable site sessions.
- One planned re-login/invite-reissue cutover.
- Proposed feed limits and event-retention/backlog caps.

No implementation, feed activation, NPM edits or DNS changes should be inferred from this documentation-only task.

## User addition: dedicated Tailscale services

In Task 1 inventory existing tailnet policy and verify enrollment-key reuse/expiry without printing its value. In Tasks 7 and 9 add one official, pinned Tailscale service and persistent identity per RAuth node; carry policy, events and replicated state through those service addresses. Preserve private local NPM ingress, restrict tailnet peers/ports, keep TLS, and test restart/re-enrollment, sidecar outage and distinct identities. Store the supplied join key only as a bootstrap secret outside Git, remove it from the runtime after enrollment, and never clone node state. In Tasks 11/12 verify there is no dependency on the host's existing Tailscale daemon for RAuth cluster traffic.

## User additions: third state host and host bind mounts

Use third state host as the third state-node candidate after live storage/latency checks, with every RAuth persistent path under /mnt/usb1/rauth. Live mount, free-space, memory and TUN evidence is saved outside Git at the private storage preflight. All deployment templates and tests must cover image VOLUME destinations with explicit host bind mounts; do not create named or anonymous volumes. Check the expected filesystem before creating a directory so an absent USB device cannot redirect writes to the system disk. Include state, WAL, etcd, GeoIP/feed snapshots, event databases/spools, Tailscale identity, certificates, configuration and backups in the path manifest and restore tests.

## User addition: default Eworx IP feed

Use https://blocklist.eworx.at/api/v1/raw as the managed built-in IP feed. Existing public rules are backfilled once, and new public rules inherit it by default; an administrator can explicitly change an individual rule selection through the step-up-protected UI. Login-required rules are not automatically changed. Keep the built-in catalog entry enabled at this fixed source; normal last-good update behavior applies.

Bootstrap and validate its snapshot before switching the runtime/NPM routes, using the packaged rauth-feed-bootstrap command while the previous feed-serving route remains available. This avoids a cold-start loop if the feed URL itself is behind RAuth. A pending/missing default snapshot must deny affected public rules rather than permit unrestricted access. Preserve explicit per-rule choices on subsequent starts. Validate using the actual HTTPS response as well as deterministic fixtures; ordinary CI tests remain independent of external feed uptime.


## Explicit worker networking and policy freshness gates

Tasks 7 and 9 use network_mode: service:tailscale for workers and colocated state
services. Private state/API listeners bind service tailnet addresses with
peer/port ACLs and TLS authorization. Local NPM ingress uses only a host-gateway
bound auth-port publication plus source/destination firewall rules for the NPM
container. Keep the sidecar off the shared NPM network. Validate positive and
negative routes, bindings, ACLs, TLS, independent health and namespace-owner
recreation before rollout. These identity-only bootstrap Compose files do not
provide an application forwarding path on their own.

Task 7 also implements HA-authoritative policy-head checks every ten seconds
and a 120-second freshness lease (maximum configured 300 seconds). A current
matching head renews the lease without the control host. A newer head withdraws
public readiness until fully applied; an unreachable head permits only the
remaining lease, then public requests return 503. Restarts require a fresh head
check. Task 10 tests disconnected-but-reachable workers, public-rule removal,
country/feed changes, expired leases and restart during controller outage. A
failed external feed download alone keeps last-good data while the unchanged
HA policy head continues renewing freshness.


## User requirement: master database only for GeoIP

Tasks 7/9: distribute only the master's local GeoIP database through the verified
policy bundle. Keep all country lookups local on each node, with no external GeoIP
API or per-request dependency on the master. Retain the last complete verified
copy during source outages and fail closed where a country restriction cannot be
evaluated. Test absent/error/empty country data with HTTP egress trapped; verify
that workers never run the database updater.
