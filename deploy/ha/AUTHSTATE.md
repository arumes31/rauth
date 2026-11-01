# SQL authentication authority cutover

SQL mode is source support for the active-active rollout. It does not make a
single PostgreSQL server highly available or complete worker/policy/SSO rollout.
Do not activate it in production before the HA state and cross-node acceptance
checks in the approved plan pass.

## Persistent configuration

Keep SERVER_SECRET unchanged across every node; it also encrypts existing TOTP
secrets and cookies. The process initializes it independently of Redis. A durable
keyed fingerprint rejects a node configured with a different SERVER_SECRET.

Set AUTH_STATE_MODE=postgres, AUTH_STATE_KEY_FILE=/run/rauth/auth-state.json,
and AUTH_STATE_ABSOLUTE_MINUTES (default 43200, maximum 525600). Idle validity
must be at least one minute and no greater than the absolute duration. All
session, proof and security-counter authorities switch together.

The key file contains index_key, active_key_id and encryption_keys (a map from
key ID to secret). Each secret is a separately generated cryptographically random
32-byte value encoded as standard base64. Use at most three encryption keys.
The index key is stable, separate from SERVER_SECRET and every encryption key.
Retain all still-used key IDs during rotation. Missing/mismatched/live omitted
keys abort startup; there is no trial-key or Redis fallback.

Bind-mount the private file read-only from the node's host persistence tree.
Use restrictive owner permissions. Keep it out of Git, logs and Docker volumes.
The third state node's source path must remain below /mnt/usb1/rauth, after a
mountpoint check. The loader requires an absolute regular file, bounded JSON,
known fields and exactly decoded key sizes. It never reports secret contents.

PostgreSQL connections require sslmode=verify-full, the cluster CA, verified
hostnames/IP SANs and a writable primary. Do not add an unverified TLS fallback.
Leader-aware database endpoints must close existing connections when leadership
is withdrawn, and promotion requires the separately verified fencing/quorum
configuration. Source checks alone do not fence a partitioned primary.

## Coordinated offline procedure

1. Back up the durable database, key files and configuration; verify the restore
   procedure in isolation. Confirm the durable Redis-import marker already exists.
2. Drain and stop every old authentication writer, including login/2FA, validation,
   admin changes and background jobs. Verify the actual running fleet; a flag or
   container health check does not prove old binaries have stopped.
3. Run the reviewed rauth-authstate-cutover command with --expire-legacy-state,
   using the shared database/key configuration. This additive migration deliberately
   ends legacy sessions, pending login/setup/passkey ceremonies, invitations and
   step-up grants. Reissue outstanding invitations afterward. Stable account IDs,
   password hashes, factors and recovery codes stay in the durable store.
4. Wait until its ready_after database timestamp. The two-minute gate ages out
   legacy TOTP proofs before new logins can accept the same still-valid code.
   Security counters start fresh during this one-time offline transition.
5. Start every enabled RAuth instance in postgres mode with the same index key,
   payload keyring and SERVER_SECRET. Test fresh password/2FA/passkey/recovery,
   revocation and cross-node flows before reopening ingress.

The durable marker makes the command idempotent: running it again does not bump
account generations or delete live SQL sessions. Compatible binaries refuse to
restart in redis mode after cutover. Older binaries do not understand this guard
and must remain stopped. Roll back to a compatible SQL-authority binary, never
restore stale Redis authorization or an older credential database.

SQL readiness checks the selected authority and primary without pinging Redis.
Missing authority, unavailable database, unverified TLS/key configuration and
activation quarantine prevent authenticated startup. Missing/revoked sessions
remain login failures; backend failures return 503 for private validation/pages.
Valid local public policies can still authorize anonymously, with country/feed
restrictions enforced first. Durable offline policy freshness and separate worker
readiness remain part of the later worker stage, not this startup change.

Cleanup is bounded and cancels on shutdown. Per-batch commits preserve progress
when a large expired-state backlog exceeds one maintenance interval.
