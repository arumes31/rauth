# Policy notifications and node confirmations

The controller emits a bounded private SSE hint after successful publication.
A worker uses the hint only to wake its independently budgeted HA-head check;
no notification renews a policy lease, supplies a payload or bypasses signature,
cache, source-profile or freshness validation. Ten-second reconciliation remains
independent of the controller. Connections renew after 45 seconds, one per node
and at most 64 total; lines, bytes and notice counts are bounded. The existing
source-bound, pinned TLS 1.3 client uses no environment proxy or redirects.
Current enrollment/scope is rechecked at connection start and every five seconds
or new notice, and the certificate deadline also ends the stream.

Policy receipts use the same policy:read capability as the policy synchronization
exchange. The server derives node identity and SPKI from the authenticated
certificate and rejects a submitted node ID. Only assigned nodes can submit.
Reports refer only to known committed manifest identities. Ready reports require
matching applied/desired identities and an unexpired bounded lease. The SQL
upsert checks current enrollment, service address, pin and scope again. A 204 follows transaction
commit. A five-second asynchronous heartbeat uses a dedicated one-connection
pool on control and a bounded private request on workers; receipt failures never
block authentication or determine worker readiness.

The admin-only Policy Sync panel shows saved source revision, published revision
and each assigned node's last applied/desired report. A report must be recent,
ready, lease-valid, still enrolled and sent with a currently enrolled key before
it confirms the current head. Missing, revoked, expired or old-head reports are
pending. Publication also must have recently captured the exact current saved
source revision before the UI can say all assigned nodes confirmed this policy.
The UI displays last reports, not a promise that a machine cannot fail after it
reports. Unavailable refreshes clear the previous success indication.

Every successful application policy-mutation transaction increments the durable
source revision in that same transaction, including changes that do not require
a new signed policy head. Capture reads the revision with rules/feed versions in
its repeatable-read snapshot. Failed mutations roll back the revision. This
prevents acknowledgments for an old policy from confirming a newer saved edit.
GeoIP remains the master's local MMDB, copied through signed policy distribution;
no external country lookup service is introduced.

## Migration and grants

Migration 0011 creates the source singleton and receipt table; 0012 binds receipts
to the observed service IP. Existing address-less reports remain unconfirmed until
a new matching report arrives. Workers continue
to check the exact migrated schema without DDL; upgrade control/schema before
starting the matching new workers. Older binaries that require the earlier schema
versions cannot be used as a restart rollback after this migration without a
compatible schema restore or a reviewed compatibility release.

Add SELECT on cluster_policy_source_state to the control source role. Its
publisher credential additionally needs SELECT/INSERT/UPDATE on
cluster_policy_receipts and SELECT on cluster_nodes and
cluster_policy_source_state. The existing publisher manifest/head grants remain.
The runtime opens a separate one-connection status pool with this credential;
receipt traffic does not borrow publisher or authentication connections. Worker
SQL roles gain no writes for this feature.

This implements synchronization observation, not durable request-event delivery.
The request-event spool/collector and three-host infrastructure/fencing acceptance
remain separate rollout gates. Do not apply production NPM routing from this
source milestone alone.
