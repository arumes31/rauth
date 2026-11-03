# Event retention and ingestion across WAN links

Status: approved by the user on 2026-11-03.

## Observed failure

Both revision 14982 canaries automatically recovered their original-session live feed and Stats after the single 35-second Hodus SQL interruption, with no app restart or manual database cleanup. The test still failed its 70-second two-node durable-event-history assertion. Retain this failed result; do not label it a full acceptance pass.

Read-only native evidence shows both local bbolt outboxes ready, zero dropped/uncommitted events and more than 500 pending events each. Central telemetry stopped at 02:24:55 UTC, before this interruption. At 02:57 UTC, central history retained 51,482 events, 275,258,316 accounted bytes,264,368,214 telemetry bytes, and 1,041 telemetry records older than 24 hours. The event-role query was a per-row statistics DELETE inside an uncommitted cleanup transaction. Thus the current cause is strongly supported by runtime evidence and source; reproduce it in an isolated native test before changing product code.

`trimChunk` selects at most 128 rows but executes two statistics statements and one DELETE per row, including telemetry which has no traffic aggregate. Each statement waits for the remote database. The receiver permits only 3 seconds for ingestion and maintenance 2 seconds. At24-hour retention expiry, hundreds of round trips repeatedly roll back an unfinished chunk; retrying the same work cannot clear the queue.

## Approaches and recommendation

1. Recommended: pipeline each existing bounded cleanup phase through pgx.Batch, preserving statement order, transaction boundaries and exact retention selection, plus explicit bounded WAN budgets for event ingestion only. Expiry, telemetry pressure and decision pressure remain separate phases so subsequent selections see prior deletions. This reuses existing SQL and schema, reduces round trips without a new retention algorithm, and permits committed chunks to make progress across retries.
2. Rewrite retention into grouped set-based DELETE/aggregate SQL. This can reduce statements further, but changes aggregate subtraction and selection logic at the same time and deserves a broader separate change.

A timeout increase alone leaves per-row WAN round trips proportional to the expired row count and is insufficient. Manual deletion, turning retention off or discarding the local spools would conceal this bug and is outside this design.

## Proposed behavior and constraints

Queue the same singleton-aggregate DELETE, aggregate decrement and event DELETE statements in the same order. A batch contains at most 128 deletions / 384 statements, stays inside the existing owner-token-fenced transaction and is fully drained/closed before another query. Preserve CHECK constraints, RLS, cascade sample deletion, byte/event/telemetry counters, expired decision counts, cursor pruning, telemetry-first preference, and the rule that incoming telemetry never evicts decisions. Update accounting atomically in the same transaction; rollback a failed chunk, never ACK uncommitted work. Previously committed chunks may remain after an overall request timeout, as today.

Use bounded event-only ingestion budgets of 10 seconds at the receiver and 15 seconds at the sender, and 10 seconds for periodic central maintenance. Keep the four receiver slots, bounded upload body/batch, pool limits, synchronous commit, server statement/idle/lock timeouts and all authentication budgets unchanged. The event-only mTLS client uses a 14-second response-header budget inside its 15-second overall deadline, covering authorization and ingestion; other private RPCs keep their existing 10-second header and 60-second overall defaults. The longer parent context allows a finite number of WAN round trips; individual server statements still have their existing deadline. Retention can commit partial progress even when a large backlog needs another attempt. A context-aware writer gate drops canceled waiters promptly; periodic maintenance releases it between committed chunks so queued uploads can proceed. Do not spin unboundedly or hold a request beyond its context.

No auth/session/key change, event schema migration, external Geo service, new dependency or deployment topology. All local queues remain persistent host binds. Capture measured completion/progress at 150 ms and 250 ms synthetic write delay and actual inter-site timings; 250 ms alone is not a failure criterion.

## Acceptance

Reproduce baseline starvation in a separate native PostgreSQL test database using the existing delayed-connection wrapper, actual populated telemetry older than 24 hours and a bounded context. Prove patched cleanup commits progress and eventually delivers a new decision under bounded retries, including at 250 ms delay. Prove exact mixed aggregate/counter totals, sample cascades, telemetry-cap pressure, duplicate batches, rollback of a failing chunk, stale-owner rejection and cancellation. Existing full eventstore/eventrelay/spool and affected runtime tests must pass. Preserve the orphan-lock tests from PR806.

Open a PR, run local review and required CI, resolve valid findings, then merge under existing user authorization. Use CodeRabbit within included usage only; respect quota and never enable paid credits. Distinguish incomplete advisory runs from passing reviews.

Roll the exact approved build onto the Hodus and NL replica canaries one at a time with full closed-state backups and SHA/authority/process guards. Verify the existing queued decisions are delivered, local pending counts return to baseline, both central node snapshots become fresh, and the original cookies/app identities survive recovery. Run the protected live-feed/Stats/filter/diagnostic suite and a new uniquely tagged, automatically reverted canary SQL interruption only after normal delivery is restored. Preserve every prior failed test. Recheck 4,155 exact durable marker payloads through all 3 routers. No further host reset is authorized.
