# Authoritative private node enrollment

Private node requests use the current cluster_nodes row in PostgreSQL, in
addition to the cryptographic TLS checks in clustertransport. Tailnet membership,
forwarded headers and browser sessions cannot create a registry grant.

Each enrollment fixes the cluster/node identity, role, dedicated service IP,
one or two certificate SPKI pins, explicit scopes, enabled state and expiry.
Every RPC authorization checks the actual socket source and verified TLS node/key
against a fresh writable-primary read. There is no positive permission cache.
Revocation, scope removal and old-key removal apply to requests authorized after
the update commits, including reused TLS/database connections. An in-flight
operation retains its already authorized bounded lifetime; streaming handlers
must reauthorize periodically. A revoked worker's separate database credentials
and public serving capability also require deployment revocation/draining.

The dedicated registry reader needs only SELECT on cluster_nodes and schema
USAGE. A separate operator/control registrar uses INSERT/UPDATE. Workers never
receive registrar credentials. Current node host configuration includes distinct
registry URL files for all nodes and registrar URL files only for control nodes.
URLs retain verified TLS and writable-leader selection. Registry reads must have
a connection budget separate from authentication, event ingestion and policy
payload downloads.

Registrar.Put creates with expected revision 0 or replaces one exact positive
revision. IP assignment is unique within a cluster, two pins allow controlled
rotation, and stale updates cannot overwrite a concurrent revocation. Lookup
returns public metadata and revision for operator comparison/recovery. Failed or
ambiguous commits require re-reading state before retrying. Expired entries can
still be explicitly disabled. Never re-enable a node from a stale saved record.

There is no public enrollment endpoint or automatic trust of a certificate just
because the private CA signed it. Provision certificate keys outside application
containers, verify actual dedicated service addresses and install least-privilege
SQL grants before enabling private listeners. Verify TLS and node permissions on
every request; errors are generic and disclose no submitted values or SQL DSNs.

Migration 0010 adds enrollment only. It does not enroll production nodes or enable
main startup, private APIs or workers. External leader routing, strict-sync HA and
fencing remain necessary: local primary/read-only checks cannot distinguish an
unfenced writable former leader. Do not authorize against an async replica.

Tests cover exact node/key/source/scope, rotation and immediate revocation on a
reused database connection, database-time expiry, cross-cluster isolation, stale
and concurrent writers, pool exhaustion/deadlines and read-only authority. A real
SELECT-only database role can authorize but cannot INSERT/UPDATE/DELETE or use the
registrar. An HTTP gate composition test reuses synthetic verified TLS state and
checks source-header spoofing, operational 503 and committed revocation; real
TLS handshakes are covered separately in clustertransport. Actual dedicated
Tailscale wire and deployed revocation acceptance remain rollout gates.
