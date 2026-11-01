# Opt-in control and worker startup

CLUSTER_CONFIG_FILE selects the existing private Linux node document. Without it,
legacy standalone initialization is unchanged. The loader supplies the auth SQL
URL, cookie secret, auth keyring path and explicit application listen address
before validation or database initialization. A cluster node requires SQL
authority, canonical SSO, exact proxy peers, frozen security settings and disabled
automatic Cloudflare mutation. The config path is operational, excluded from the
non-secret node fingerprint.

Additional node document fields:

- public_listen: literal private Docker-bridge IP and nonprivileged port; no
  wildcard, loopback or service-Tailscale application bind.
- cookie_secret_file and auth_state_key_file: existing private host files below
  data_root and outside the complete cache subtree.
- database_files.auth: verified-TLS URL selecting the writable leader, alongside
  the separate registry/head/payload/control-source/publisher capabilities.
- geoip_file: optional control-only public GeoIP source below data_root, outside
  the cache, with a pre-existing private parent directory on the same device.

Every cache/source directory is checked without following symlink components and
must remain on the configured persistence device. Missing directories are not
created by this bootstrap. GeoIP source files may be readable (0644) but not group
or other writable; directories and ownership remain guarded. Host deployment must
verify filesystem UUIDs and supply explicit binds; all Pi3 paths remain below
/mnt/usb1/rauth. Secrets/certificates retain stricter private-file permissions.

Control initialization migrates the schema. Workers perform a bounded SELECT-only
check of the exact embedded migration versions and never run DDL. Both require
the already committed shared SQL authority, fleet cookie/keyring compatibility
and cutover quarantine. WebAuthn initialization must succeed in cluster mode.
No startup command silently performs Redis-to-SQL cutover.

A node checks its own current enrollment/key/IP/role before serving. Independent
pools reserve head (1), payload (2) and registry (2) connections; control capture
and publication each use one more. Authentication retains its existing pool.
Capacity and actual HA/leader withdrawal need measured deployment acceptance.
The policy worker restores verified cache but starts unready until a fresh HA
head matches. The controller independently reconciles complete signed source
policies. Both listeners bind before reconciliation/publication starts.

Request-feed observation wraps policy admission. Every public auth/UI request
pins a complete fresh snapshot. Liveness, readiness, metrics and static files do
not require the pin; metrics keep their existing source authorization. Cluster
readiness checks snapshot freshness, SQL authority and current own enrollment,
rather than the standalone GeoIP/feed globals. Public readiness output is generic.
The private status API exposes only node/revision/lease state under mTLS and
current status:read permission.

Workers run no source fetchers, global rule refreshers, bootstrap accounts or
maintenance. Only control runs feed/GeoIP source updates and existing account/
cleanup maintenance. The controller does not start the out-of-band Cloudflare or
rule refresh loops. Source cache updates do not authorize requests: the pinned
compiled snapshot supplies rule/feed/country decisions.

Workers register no local admin mutation routes. Administration on the canonical
auth host is relayed to the exact enrolled controller over source-bound mTLS and
current admin:relay permission. A bounded envelope preserves only the canonical
management path, browser cookies, origin/CSRF fields, original client IP and body.
No forwarded identity/forwarding/hop headers grant access. The controller rebuilds
the original HTTPS request and independently runs browser authentication, admin
permissions and CSRF checks. Redirects and multiple cookies are preserved. SSE
chunks are flushed immediately; the bounded private client connection may renew
through the browser's normal reconnect behavior. If control is down admin returns
503 while local login/2FA/profile/forward-auth remain independent.

This source still needs complete Linux main-process/mount/PKI integration,
positive real-MMDB resource tests, fleet desired/applied UI and acknowledgments,
policy notices, durable event spooling/collection and actual
three-host strict-sync/fencing infrastructure before worker/NPM cutover. Existing
unit/SQL/relay checks are not a proof of deployed host-loss or physical passkey
acceptance. Never enable an incomplete rollout merely because source compiles.

Offline helpers in the image use the same guarded bootstrap when
CLUSTER_CONFIG_FILE is set. The feed bootstrap and explicit authority-cutover
command require the control role. rauth-node-profile -node-id <UUID> derives only
the public security fingerprint/GeoIP requirement from the node's environment;
it makes no database connection and can run before private material is installed.
Cluster client-IP extraction uses the frozen configured Cloudflare prefixes,
which must be canonical networks, without relying on a mutable process-global
updater. Actual peer/source measurements remain a deployment preflight.
