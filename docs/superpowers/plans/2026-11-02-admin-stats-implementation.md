# Admin Stats and processing-node implementation plan

Approved design: ../specs/2026-11-02-admin-stats-design.md. Preserve the active-active rollout and event work in 2026-11-01-public-access-active-active.md; this extends it rather than replacing HA/worker/NPM deployment.

## 1. Finish the event transport/runtime integration

Base the implementation on the bbolt/PostgreSQL storage component. Finish internal/eventrelay with bounded streaming decode, authenticated EventsWrite attribution, post-commit exact-ID ACKs and separate live/catch-up budgets. Wire optional guarded event configuration and private controller event credentials without giving workers event-database credentials. Capture the pinned policy revision and processing duration in the existing RequestFeed wrapper; keep the original source-IP/proxy rules.

Start persistence/collector/delivery actors outside the request path. Event failure must not change authentication or policy readiness. Add cached local event health to private node status. Finish persistent admin SSE with durable cursors, bounded replay and visible history/display gaps. Avoid per-viewer repeated full-database scans by sharing live committed batches, retaining a bounded cache and using dedicated history read capacity.

Checks: strict fake-verified-TLS composition tests are unit evidence, not real handshakes; prove actual source-bound pinned mTLS and login-protected SSE separately in the isolated multi-host canary. Exercise collector down, lost ACK, revocation, independent catch-up/live progress, process restart, queue/retention/full-file gaps and cancellation.

## 2. Extend the event contract for processing node and telemetry

Update internal/requestevent, eventspool and eventrelay with bounded typed decision duration and essential metric snapshots. Decision records carry stable processing node ID/name, occurred/received times, policy version and processing microseconds. Essential telemetry snapshots carry node and process-instance IDs, sample time, fixed counters/histograms/gauges and coverage/reset metadata. Do not add credential, cookie, body or URL query/fragment fields.

Collect in background at a default five-second cadence. Durable snapshot IDs survive retries. Treat missing/reset intervals explicitly and never manufacture per-minute values from a large endpoint delta. Bound payload bytes, field/label sets and every in-memory queue. Keep current diagnostics families sanitized and scoped; cap optional/raw family payloads separately.

## 3. Add central schema and aggregation migration

Use an additive event-store migration after version 1; do not edit an already-applied schema in place or add event tables to auth migrations. Add normalized indexed decision dimensions and typed telemetry/node-observation tables. Maintain low-cardinality traffic/histogram rollups from newly inserted decision records, with duplicate delivery contributing zero additional counts. Record late/replayed updates by occurrence time and preserve received time for delay/coverage.

Use bounded age/byte retention for raw data and aggregates. Keep high-cardinality IP/URL top-N work on indexed event data with query deadlines and pagination, not unbounded metric labels. Select chart bucket widths to return at most roughly 600 points per series (5m/1h/24h/7d). Provision non-owner runtime roles and separate bounded ingestion, history-reader and stats-reader pools. Recheck the ordinary operator path and row isolation with real PostgreSQL roles.

Checks: upgrade a populated version-1 fixture; restart epochs/cursors; exact dedup/aggregate totals; histogram quantiles; out-of-order replay; pruning watermarks; counter resets; ordinary operator/no-DDL runtime roles; bounded query plans. Take a private compatible backup before any canary upgrade.

## 4. Build the statistics service and safe endpoints

Add a typed statistics service over the event database and cached node observations. Provide bounded initial/history data and coalesced live snapshots. Node/time filters apply globally; country/domain/action and URL/IP drilldowns apply to traffic views with their scope labeled. Return unavailable/stale/partial coverage explicitly.

Add GET /rauthmgmt/stats, protected data/history/export and SSE endpoints. GET /stats redirects to the canonical admin page without returning data. Reuse existing admin session/canonical-origin protections, revalidate ongoing streams and retain a combined per-user/total stream budget. Workers relay admin requests privately. Preserve /metrics ACLs.

## 5. Add Processing node to the live feed

Update the live-feed template and static/js/management/live-feed.js. Show a Processing node cell with name and stable-ID detail, include it in search and provide a node filter. Keep original client IP as its own cell. Render all request/node text with textContent, show replay delay and cumulative/unknown loss information, and preserve bounded DOM rows/pause/reconnect behavior. Add narrow CLI DOM regressions.

## 6. Build the responsive Stats page

Use native templates, local JavaScript and SVG charts consistent with existing dark/light admin themes. Add the filter bar, request/auth summary cards, request/action timeline, latency percentiles, country distribution/map, top URLs/domains/IPs and denial reasons. Add a paginated decision drilldown. Ship map shapes and attribution locally; no external geolocation/analytics/tile/chart request is allowed. Provide table alternatives, keyboard controls and explicit loading/empty/stale/error states.

Add node resource panels, policy/feed/GeoIP/spool/delivery panels and expandable registered-metric diagnostics. Show sampled histories and coverage gaps honestly. Global shared gauges such as active sessions are read once from authoritative state and are not summed from repeated node observations.

## 7. Complete metric instrumentation and HA observation

Map existing login, failure, rate-limit, active-session, audit, GeoIP, recovery and bypass metrics. Add bounded forward-auth decision/latency counters and missing 2FA outcome telemetry at actual success/failure boundaries. Aggregate counters by node/process incarnation with reset handling. Observe Go/process resources in background. Observe the HA state through a narrowly scoped monitoring path and whitelist fields; never return SQL URLs, replication credentials or raw connection configuration.

## 8. Validate failure behavior and resource budgets

Run focused Go/verified-TLS PostgreSQL/native bbolt tests, frontend CLI DOM tests, both platform static analysis, vulnerability checks and ARM64 builds. Use included CodeRabbit reviews only when available; respect cooldown/free limits. Verify stats authorization and stream revocation. Test collector/database outages, duplicate ACKs, lost telemetry, restarted nodes, mixed late data and missing coverage.

Measure auth latency and event throughput while stats queries/catch-up are saturated. Enforce separate connection/query/rate budgets and reserve physical database/WAL/local-file capacity. Verify all persistence is host-bound, with Pi3 mount UUID checked before creating paths under /mnt/usb1/rauth. Browser/passkey checks previously blocked by policy remain human acceptance; do not bypass through another backend.

## 9. Merge and roll out within the original HA plan

Keep PR descriptions source-focused; private infrastructure evidence stays outside Git. Merge only the expected tested head when current checks/reviews are green. Complete actual three-host strict-sync HA/fencing/restore and production auth cutover before claiming host-loss support. Deploy all authorized NPM workers, preserve existing protected routes, add exact public aliases and processing-node labels, verify event/metrics replay and new login/2FA across nodes, and complete real host-loss/resource acceptance.
