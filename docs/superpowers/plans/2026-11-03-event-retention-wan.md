# Event retention WAN implementation plan

Design approved by the user on 2026-11-03. Implementation and isolated native verification follow this plan.

1. Add a native regression in internal/eventstore using the existing delayedStatsConn pattern and a separate test database. Seed mixed decisions/telemetry, advance the Store clock past 24 hours, use explicit 150 ms / 250 ms write delays, and capture baseline timeout with zero retention progress. Do not touch the live canary database.
2. In internal/eventstore/store.go pipeline bounded retention phases with pgx.Batch, preserve SQL ordering/accounting/fences and close every BatchResults path. Add focused mixed-selection/aggregate/cascade/rollback/cancellation/stale-owner coverage. Make writer admission context-aware and yield between committed maintenance chunks, with real SQL barrier coverage.
3. Define documented event-only bounded budgets in internal/eventrelay/relay.go and cluster_events.go: receiver 10 s, sender 15 s, maintenance 10 s. Test cancellation and bounded receiver admission; authentication budgets unchanged.
4. Run the complete native eventstore/eventrelay/eventspool and affected runtime suite, focused vet and compilation. Inspect diff and meaningful branches. Respect CodeRabbit included quota; do not use paid credits.
5. Commit, open PR with baseline/fixed native evidence, resolve valid review findings, wait for required checks, audit advisory outcomes, merge exact head when acceptable.
6. Build/stage immutable artifact. Verify healthy HA plus 4,155 markers; full closed-state backups and replica-only canary update guards. Never restore an older spool/auth snapshot over newer writes.
7. Prove backlog drain with existing queued event IDs, fresh metrics/processing node and original-cookie reconnection; full Stats/feed suite; single separately tagged automatic-cleanup SQL interruption; final exact-marker/health evidence. Keep all failed proof artifacts.
