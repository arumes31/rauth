# Bounded event collector recovery after cross-site SQL interruptions

The real 35-second canary SQL interruption exposed an orphaned PostgreSQL session holding the central event collector advisory lock. Authentication recovered, but new collectors could not acquire the lock and Stats/live-feed history remained unavailable for more than eight minutes. The exact canary session, database/user/client and cluster advisory-lock key were verified before a single scoped backend cleanup; production was untouched. Browser stream retry behavior is separately fixed in merged PR805.

## Approaches

1. Keep the existing advisory lock and owner-token fence, but make the dedicated lock session expire on the database server after 30 idle seconds. The existing two-second collector health checks heartbeat that exact connection. Always destroy its connection on close so an advisory lock can never return to the shared pool. This is the recommended narrow fix: no event schema, key, auth, spool or deployment topology change.
2. Replace the advisory lock with a persisted SQL row lease and new renewal/fencing contract. This would need a broader schema and compatibility change; the current owner-token transaction fence already provides stale-writer rejection.

The first approach is proposed. The 30-second timeout applies only to the dedicated event lock session, not pooled auth/history queries or global PostgreSQL settings. A broken collector may leave its server session alive temporarily; PostgreSQL expiry releases it without an operator intervention. Existing owner-token checks still reject an old writer after a new collector takes over, and ACKs still follow synchronous commit.

## Implementation and acceptance

Set idle_session_timeout on the reserved lock connection when acquiring its advisory lock. Bound active server work on that session with a five-second statement_timeout, because idle expiry does not run during a query; a disconnected active statement can therefore take up to five seconds before its 30-second idle expiry begins. Serialize heartbeat and close on that pgx connection; report unavailable if its heartbeat fails. Hijack and close the dedicated connection rather than releasing a possibly locked session to the pool. Preserve bounded contexts and existing actor retry behavior. No new background service, dependencies or global DB configuration.

Native tests must demonstrate: unchanged baseline retains an abandoned lock; patched lock expires and a second Store opens; heartbeats prevent expiry while healthy; the first owner cannot commit/ACK after takeover; repeated open/close does not leak advisory locks or connection capacity. Use isolated test databases only. Then review/CI/PR/green merge under existing authorization, followed by replica-only canary upgrade and one bounded SQL-connection interruption with automatic cleanup. Browser retry/original-cookie recovery and delayed durable event delivery must succeed without manually terminating a database session or restarting the app. Record WAN timings rather than imposing the former LAN latency target.

PostgreSQL references: https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-IDLE-SESSION-TIMEOUT and https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS .
