# Opt-in Linux host configuration

`internal/clusterconfig` parses and loads existing private node files. When
`CLUSTER_CONFIG_FILE` is set, role-aware startup consumes this configuration
and performs the documented authority, listener and schema checks. Standalone
startup remains unchanged.

A schema-1 node document specifies control/worker role, cluster/node UUIDs,
the node's own literal Tailscale service address and private port, exact data
mount path/device/filesystem, cache path, node certificate/key/CA, public policy
keys, separate database URL files, and the controller's enrolled identity,
literal service endpoint and one or two SPKI pins. Control nodes additionally
need a policy signer and desired profiles; workers reject these capabilities.
All file/cache paths must be distinct and below the data root. The node document
itself must also be below that root. The entire cache subtree is reserved for
policy-store data: protected files and the node document cannot be inside it or
be an ancestor of it. This prevents cache journal writes or garbage collection
from colliding with configuration or keys.

Load requires an existing private Linux bind mount matching the configured
major:minor device and ext4/xfs/btrfs/zfs filesystem, writable at both mount and
superblock levels. It never creates a directory or falls back to the system disk.
The deployment wrapper must verify the host filesystem UUID before creating
paths or Docker services, resolve the current device number on boot, and use
bind mounts with automatic host-path creation disabled. On Pi3 **every persistent
path is below /mnt/usb1/rauth**, with the USB mount verified before startup.
This application check does not prove a host bind's source path, disk durability,
or fencing; those need separate host/deployment acceptance.

Private reads open each path component without following symlinks, reject FIFO
and nonregular files without blocking, and check the opened file's owner and
permissions. Files must be owned by root or the runtime UID and have no group or
other permissions. The data-root directory allows no group write/other access.
Keep config/secrets writable only by the trusted deployment operator. Linux is
required; non-Linux host loading is explicitly unsupported.

Node credentials must match the exact node URI, dedicated service IP, trust chain
and client/server usage. Controller pins must include its own current node key.
Policy signer keys must be separate from node and CA keys. Controller signer JSON
is {"key_id":"...","seed":"base64-32-byte-seed"}; signing/verifying a probe checks
that its public key is enrolled. No signer material belongs on workers.

Each database file contains a PostgreSQL URL with explicit host, username and
database, sslmode=verify-full and target_session_attrs=read-write. Every parsed
fallback must retain TLS hostname verification. Loading performs no network IO;
startup still needs separate pools/grants, authoritative schema checks, primary
checks and tested failover routing. Protect all referenced PostgreSQL TLS files
on host binds as part of deployment; the loader does not provision database PKI.

Size each authentication URL's `pool_max_conns` explicitly before expanding the
fleet; the legacy default is 20 connections per RAuth process. For example,
`pool_max_conns=4&pool_min_conns=0` permits five auth processes to use at most
20 auth connections together. Add the separate event writer and reader pools,
replication, backups and operator reserve to the server-wide budget. Validate
representative login/2FA and event load before choosing production limits;
raising PostgreSQL max_connections alone is not capacity acceptance. The URL
option is local operational configuration and does not change policy fingerprints.

Desired profiles JSON is {"schema":1,"nodes":{"<node UUID>":{
"security_fingerprint":"<lowercase SHA256>","require_geoip":true}}}.
It permits 1–64 nodes, includes the control node and rejects unknown/duplicate
fields. The actual runtime must compare its derived security fingerprint with
its own profile before publication. A parsed fingerprint alone is not enrollment.

Errors are static and never include submitted secrets. Loaded configuration and
signer/profile accessors return copies; structured logging reveals only role and
node ID. Callers must never log individual database URLs or key bytes.

Tests exercise strict JSON, role capabilities, path escapes, symlink ancestors,
FIFO/permissions/owner checks, mount substitution/read-only rejection, real
synthetic node chains, key-purpose separation, own node/IP matching, signer
mismatch, database TLS/leader selection and profile validation. Native tests use
a test-only mount-check substitute for key fixtures; the real mount parser and
ordinary-directory rejection are tested separately. Full Docker mount and
hardware removal acceptance remain rollout gates.

Included CodeRabbit CLI review identified JSON field aliases that the standard
Go decoder treats as equal. Duplicate detection now uses the same Unicode
simple-fold equivalence, including ASCII case, long S and Kelvin-sign aliases;
configuration and signer regressions cover these cases. The review completed
with one finding, fixed and verified locally; telemetry DNS errors did not
prevent the review from completing.
