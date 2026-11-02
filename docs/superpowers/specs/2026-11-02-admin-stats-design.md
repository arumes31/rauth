# RAuth processing-node feed and admin Stats

Status: approved by the user on 2026-11-02 (Europe/Vienna). The fresh builder review reported “nothing important left.” This extends the approved active-active design and user-selected local bbolt + HA PostgreSQL storage. It does not hold up the already-authorized event delivery work.

## Intent and boundaries

The live feed identifies which RAuth node processed each decision, alongside the original client IP, URL, country and colored action. Add a responsive built-in Admin → Stats page inspired by the supplied traffic dashboards. Counts describe RAuth decisions and authentication operations, with service/cluster telemetry. Request history remains RAuth-only; the previous no-NPM-log requirement remains in force. Application page-view analytics, revenue, browser engagement and origin-server response codes are outside the available RAuth data.

The only geolocation inputs are the master MMDB and verified local worker copies. Charts and a country map load all code/shapes from local static assets. Do not query external geolocation, analytics, charting or map-tile services.

## Approaches

The proposed approach is a native admin page using durable decision history, bounded per-node metric snapshots and local SVG charts. This supports node filters, outage replay, shared authorization and both admin themes without a second dashboard service. An alternative is a live-only page over current Prometheus counters: smaller initial work, but no reliable past-window charts or reconstruction across outages/restarts. An external dashboard service adds another deployment and authentication surface, while the user explicitly requested a RAuth admin page. The native durable approach is the recommendation submitted for approval; query/chart implementation details remain builder calls.

## Page and routes

Add a Stats navigation entry and an actual GET /rauthmgmt/stats page. GET /stats redirects to that canonical admin route without returning metric data. GET /rauthmgmt/stats/data supplies bounded initial/historical data; an admin-only SSE stream pushes live changes. Retain /metrics and its existing access controls. Add a protected diagnostics view/download for the full registered, sanitized node metric families; do not make metrics publicly accessible as a side effect. Worker administration uses the existing authenticated private controller relay.

Every data/export/stream route uses the existing browser session, administrator, canonical-host and origin protections as applicable. Streams retain ongoing session/admin revalidation and connection/write limits. No metrics response contains credentials, session tokens, cookies, request bodies or URL queries/fragments. Raw client IPs remain administrator-only and follow event retention.

## Layout and interaction

Use existing RAuth dark/light styles, typography and accessible controls, with a compact sidebar link, a filter bar and a dense desktop dashboard. Stack cards and charts on phones; show table labels per row and keep long URLs scrollable/wrapped. Use text labels in addition to status colors.

The header provides time range (5m, 1h, 24h, 7d), node selection, live/pause, last update and data coverage. Node/time filters apply throughout. Domain, country, action and URL/IP searches drill into traffic panels; system and HA panels keep their node/time scope visibly labeled.

Top cards: processed decisions, current request rate, allowed/blocked/login-required totals and shares, errors/rate limits, p50/p95/p99 RAuth decision latency and active auth sessions. A wide request/decision timeline sits above country distribution/map, action breakdown, top domains/URLs, top original source IPs and denial reasons/matched feeds. Clicking a country/bar/row opens a filtered, bounded decision-history view.

Node panels show processing node name plus stable ID, last seen, application readiness, uptime/version, CPU, RSS/heap, goroutines/GC, request/auth rates and latency. Separate operational panels show auth database/HA state, event database state, policy desired/applied/lease, feed/default-blocklist version/freshness, GeoIP version/freshness, local spool age/bytes/count, drops/unknown-loss markers and delivery/catch-up state. Existing login success/failure, rate-limit, recovery-code, bypass, audit and GeoIP counters are included. Expandable diagnostics expose the other registered Go/process/Prometheus metric families with units and scope.

A node that stops reporting is shown as stale/offline with its last observation time; missing samples are not zeroes. Historical graphs mark retention, restart, replay and unavailable-coverage intervals. Replayed data keeps its original timestamp. Global shared gauges such as active sessions are read once from authoritative shared state, not summed across nodes.

## Collection and correctness

Processing node identity comes from the authenticated node certificate/enrollment at central ingestion and must match the record; a client header cannot select it. Human-readable names are display metadata associated with that ID. Capture decision duration around RAuth processing with a monotonic timer. It measures authorization processing, not application response time.

Collect bounded metric snapshots in background actors, never on the request admission path. Tag counter snapshots with node ID and process-instance/boot identity so resets do not become negative rates. Preserve essential snapshots through the local durable buffer and deduplicate at ingestion. Keep current node gauges separate from historical aggregates. If a sampling interval is missing or only endpoint totals survive, mark its timing coverage rather than inventing per-minute precision.

Use the dedicated central event database, its own roles and bounded ingestion, history-reader and statistics-reader connection/query budgets. Do not query large event histories through the authentication pool. Generate indexed normalized event columns and low-cardinality time aggregates in or after durable ingestion; deduplicated retries must not increment aggregates. Expire aggregates with the documented seven-day event retention. Top-N views, pagination, query deadlines and time ranges are bounded. No unbounded label sets or full-table analytics scans run on each live refresh.

The central event database shares the planned HA PostgreSQL instance, so WAL/CPU/I/O capacity and saturation acceptance remain necessary. Auth readiness never depends on telemetry collection or Stats availability. A collector/database outage leaves local durable buffers active; the central page reports unavailable/stale and catches up after recovery.

## Builder calls and acceptance

Builder calls: SVG/chart implementation, exact card grouping, fixed histogram bucket edges, bounded top-N limits, source metric-name mapping and efficient SQL rollup/index strategy. Default snapshot cadence is 5 seconds and live page updates coalesce at most once per second. Keep existing stream caps or a shared per-user combined cap; separate pages must not multiply the permitted admin stream load.

Acceptance covers original-IP versus processing-node attribution; filtering and mobile layout; counter resets/multi-node aggregation; histogram quantiles; duplicate ingest; out-of-order replay; expired/missing coverage; unauthorized/non-admin access; revocation of an open stream; offline workers and recovery; bounded storage/query/connection use; and auth latency under saturated statistics/event workloads. Existing CLI/API fixtures remain usable. Browser/passkey acceptance that was previously policy-blocked remains a separate human verification step.
