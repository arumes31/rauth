# Event collector heartbeat across WAN

Implementation follows the approved HA WAN recovery and Admin Stats design, which requires bounded database work independent of authentication.

Evidence: post-PR810 canaries intermittently return Stats503 while auth remains ready. The actual event role is unrestricted and PostgreSQL uses27/64 slots. Two callers (collector lifecycle and event observation) serialize Status through its reserved lock connection, each with a1s context. An isolated TLS PostgreSQL diagnostic with400ms per Write reproduces one failed heartbeat at1.225s; both succeed under3s.225ms also succeeds. This timing model is not an arbitrary WAN availability guarantee.

1. Define an event-only3s HealthTimeout and use it for both SQL collector Status callers. Keep local bbolt observation1s, auth deadlines, Status ownership/writable-primary predicate,30s orphan idle lease,5s server query cap, caches and collector disposal unchanged.
2. Test concurrent repeated Status225/400ms and current-owner rejection; preserve shorter caller cancellation. Run existing lock-expiry/fencing tests and cold reader tests using the isolated clone, sequentially after the authority test reservation releases it.
3. Run focused local tests/lint and one free CodeRabbit review if available. Record cooldown without retrying.
4. Review exact patch, CI and immutable binary before any new canary upgrade. No host reset or production route change.

The existing1s baseline failure is retained in ha-event-health-wan-diagnostic-v2.private.json. No archive/WAL edits are part of this repair.

Review refinement: stamp event-health CheckedAt when the completed observation is published, rather than before the probes. Keep the existing6s snapshot expiry and authentication freshness unchanged. A focused regression covers a successful observation that began more than6s ago.
