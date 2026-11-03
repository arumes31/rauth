# Cold WAN event-reader recovery implementation plan

This implements the already approved Admin Stats design and the requirement that the sites tolerate WAN latency and interruptions. That design delegates efficient SQL strategy and bounded reader/connection budgets to implementation. This is a correctness/performance repair within those boundaries, with no new architecture, authentication behavior, policy or data schema.

The existing 225 ms test warms connections and statements before measuring. Native cold-connection diagnostics instead observed a two-second Stats deadline and repeated unavailable results. A cold history read at 225 ms succeeded in about 1.82 seconds; it is not the same result as the Stats failure, and the earlier live history failure did not record its original HTTP status. Preserve these distinctions and the successful live retention/interruption proofs.

## Changes

- Give event history, Stats and metric diagnostics a five-second end-to-end read budget, including cold TLS/SCRAM, writable-leader selection and the read-only session setup.
- Give the two dedicated read pools five-second connection setup and a two-second server statement limit. Preserve writable-leader validation followed by read-only mode, the existing optional top-query limit, all roles and pool counts. A longer network/setup budget must not expand server query execution limits.
- Apply the same event-read budget to durable Live Feed history and tail reads. Preserve the three-second authorization check, periodic authorization/revocation checks, write limits, shared stream cap, cursor/replay and redaction behavior.
- Allow the event-only collector connection five seconds and collector opening ten seconds, consistent with the existing ten-second ingest budget. Authentication, policy and registry client defaults remain unchanged; event delivery stays fifteen seconds.

## Verification and release

1. Add real PostgreSQL/TLS cold-reader regressions at 225 and 250 ms per write, with delay enabled before either connection or statement preparation. Include actual target_session_attrs=read-write behavior, correct decision/diagnostic/feed results and parent cancellation. Reproduce failures on the unchanged code first.
2. Verify actual server-side reader timeout with pg_sleep while the caller budget remains available, and verify the reader remains read-only. Retain warm-reader, collector ownership/fencing, rollback/accounting and retention tests.
3. Exercise Live Feed initial history and tail lookup across the old two-second boundary through the protected HTTP fixture.
4. Run relevant native suites, compilation/vet and a milestone review within the free CodeRabbit allowance. Open a focused PR, resolve real findings and merge only after checks are acceptable; record inconclusive advisory scanners accurately.
5. Build and pin the merged runtime, retain closed app/spool copies, roll the two canaries sequentially, verify exact captured delivery and acknowledged markers, and recheck normal protected Stats/feed and automatic recovery. Do not reset hosts or modify production routes as a side effect.

Review follow-up: the worker admin relay gets its own 30-second response-header budget for up to three sequential five-second feed lookups plus authorization/WAN overhead; ordinary controller/policy/status clients retain their defaults. Revalidate the live administrator session after cold setup and before any headers or events, with the existing three-second authorization budget. Verify session revocation during both history and tail setup discloses no events, and that admin relay selects its dedicated client.

Measured WAN boundary: the observed transport samples reached 359ms. Added 400ms cold-reader/collector coverage. The first boundary run preserved a real Stats/feed failure under the five-second total read budget, while history/diagnostics/tail and collector opening passed. Use a ten-second event read/setup budget (including reader connection setup) with the independently enforced two-second SQL execution cap; the dedicated admin relay header bound therefore becomes 45seconds. Collector opening/ingest stays ten seconds, sender fifteen seconds, and ordinary/authentication RPC deadlines stay unchanged. Keep the warm225ms latency assertion independent of the larger cold setup allowance.

CI boundary refinement: native400ms collector opening passed in9.28s, but the full CI run exhausted its ten-second caller budget. Give two-session collector opening a dedicated15second bound; per-batch ingest10/sender15 and reader10/serverSQL2 remain unchanged. Preserve the failed CI run and add caller-error/elapsed diagnostics. Do not widen authentication budgets or discard pending events.
