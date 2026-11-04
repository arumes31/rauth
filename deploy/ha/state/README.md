# Isolated PostgreSQL HA acceptance fixture

This fixture implements the approved three-data-node PostgreSQL 18 / Patroni / etcd topology for testing. It deliberately accepts only `mode: isolated-test` and a separate `rauth-test-*` scope/root. It cannot render a production deployment. No production databases, RAuth configuration, NPM routes or DNS records are changed by these tools. Successful fixture tests alone do not establish host-loss safety.

## Storage and host safety

All state services share their node's existing dedicated Tailscale service namespace. Merge `compose.state.json` with that node's verified, unchanged `compose.tailscale.yml` and existing `.env`, in its existing Compose project. Do not recreate or enroll the Tailscale service. Use `up --no-deps` for only the three new services. The overlay has no host/public port publications, privileges, Docker socket or watchdog device. Test services deliberately use `restart: no`: after a host or Docker restart the operator must rerun the UUID guard before starting them. Docker automatic restart must not bypass mount verification. A supervised boot/restart guard is a separate production prerequisite.

1. Record each live host's actual filesystem UUID, mount, free space, currently available memory, clock status and independent failure-domain evidence in a private manifest. Confirm ports 2379/2380/5432/8008/6543 are unused inside its dedicated namespace. Apply peer/port tailnet policy before startup.
2. Use a root whose final component begins `rauth-test-`, separate from existing node state. All Pi3 persistence, including operator staging, certificates and backups, stays below `/mnt/usb1/rauth`. A USB node must declare `usb: true` and mount `/mnt/usb1`.
3. Render into an operator staging directory with `python3 render.py manifest.json --node state-a --output STAGING`. Example digests and UUIDs are placeholders, never deployment values. The manifest contains no credentials. Output files are private.
4. On the actual Linux host, run `python3 prepare.py expected-storage.json` first; add `--create` only after successful checks. It checks the exact live writable filesystem UUID **before creating any directory** and holds directory descriptors to that filesystem. Linux descriptor mount IDs reject even same-device nested bind mounts; device numbers alone cannot detect those. Missing mounts, symlinks, nested mounts, insufficient space/memory and substituted storage fail closed. Existing ancestors must already exist and are never chmod/chown'ed.
5. Install the rendered files and separately generated secrets/PKI without following symlinks. Set `config/patroni.json` to UID/GID 999, mode 0600, and `config/haproxy.cfg` to UID/GID 10002, mode 0600. These are individual file binds from the root-owned shared `config` directory; each file needs its own consuming UID. Secret and leaf-key files use mode 0600 with the UID of the consuming service; public CA files may be 0644. Service PKI/data directories are private to their consuming UID; shared operator directories stay root-owned. File installation and ownership are operator steps: `prepare.py` creates and checks directories; `render.py` creates private staging files. Neither installs or verifies final leaf-file ownership. Use an audited installer that opens the verified destination directory by descriptor and creates each new leaf with `O_NOFOLLOW | O_CREAT | O_EXCL`, then applies `fchown`/`fchmod` and fsyncs before startup. Reject existing or symlinked leaves rather than overwriting them. Re-run host preflight immediately before startup. Do not use `docker compose down -v` or delete state as an error recovery step.

The image's `/var/lib/postgresql` VOLUME is explicitly covered by a host bind, including the PostgreSQL 18 data layout. WAL, archives, etcd, configuration, secrets and backups have separate host paths. Automatic bind-source creation is disabled. Transient runtime files use bounded tmpfs. Initial test caps are PostgreSQL 256 MiB, etcd 128 MiB and router 32 MiB with no container swap; they are acceptance-test budgets, not validated production sizing. Before startup, verify Docker reports memory, swap and PID limit support and check the running containers' actual cgroup limits; configuration alone does not establish enforcement. Some Raspberry Pi kernels disable the memory controller by default. Any boot-setting change and reboot requires its own backup, rollback and shared-host maintenance plan. The storage preflight checks memory availability, not cgroup enforcement. The storage preflight reserves at least 650 MiB currently available memory and 20 GiB free space on state hosts. CPU limits and representative load acceptance remain rollout work.

## Images and private configuration

Build the custom image using `Dockerfile` and a verified official PostgreSQL **18.6-bookworm digest** via `--build-arg POSTGRES_IMAGE=...@sha256:...`. The complete Python dependency lock requires hashes. Program permissions are set explicitly in the image, independently of private operator staging modes; a build check reads both programs as UID 999. Build and test both amd64 and arm64; record the resulting multi-architecture digest in the private manifest. Inspect image VOLUME metadata for **all** chosen images before running them: any added volume must also have an explicit host bind or bounded tmpfs. Pin etcd and HAProxy by verified image digest. Do not substitute floating image tags.

Generate independent private PKI purposes. Never distribute CA private keys to runtime containers:

| Service directory | Files and purpose |
| --- | --- |
| `pki/etcd` | `client-ca.crt` bundles the DCS client and server roots: etcd also uses it to verify its internal gateway connection. `server.crt/key` has server-only EKU and the own service IP SAN; separate client-only `loopback.crt/key` authenticates the gateway via explicit `--client-cert-file`/`--client-key-file` flags; `peer-ca.crt` and `peer.crt/key` authenticate only the three etcd peers (client + server EKUs, own IP SAN). |
| `pki/patroni` | `dcs-ca.crt` trusts etcd servers, `dcs-client.crt/key` authenticates the Patroni DCS client; `rest-ca.crt`, `rest-server.crt/key`, `rest-client.crt/key` protect Patroni REST and peer probes; `sql-ca.crt`, `sql-server.crt/key` protect PostgreSQL. |
| `pki/router` | `rest-ca.crt` and combined `health-client.pem` authenticate TLS health checks, without the REST mutation password. |

Do not rely on etcd reusing its server certificate as a client: separate issuers/EKUs require the explicit loopback identity and both trust roots, otherwise the HTTP health/gateway cannot connect to its own gRPC server. Keep server leaves server-only and client leaves client-only.

Each REST server certificate has its own IP and `<node>.rest.<cluster>.internal` SANs. SQL server certificates have their own service IP and the shared logical DNS SAN `<cluster>.sql.rauth.internal`. PostgreSQL connections remain end-to-end TLS: HAProxy passes SQL bytes through and does not terminate SQL TLS. Add the logical SQL name to each RAuth container's `extra_hosts`, mapping to **that node's own** service IP, and use port 6543, `sslmode=verify-full`, the SQL CA and `target_session_attrs=read-write` in private URL files. No runtime DNS dependency on Hodus is introduced. Replication verifies each actual data-node IP.

Place a private `secrets/patroni-auth.json` on state nodes only, with four separately generated printable random passwords, at least 32 characters: `superuser`, `replication`, `rewind`, `rest`. These test credentials must differ from production and existing canary credentials. The entrypoint validates permissions and merges them into a mode-0600 tmpfs file; no passwords are put in Docker environment variables, arguments or the rendered config. Bootstrap creates replication/rewind users. An operator must create the `rauth_runtime NOLOGIN` group and grant only appropriate database roles membership before application tests; the group is used by source-IP-restricted pg_hba rules. Workers receive no superuser, replication, rewind or REST mutation password.

The initial DCS configuration requires strict synchronous replication to one standby, fsync/full-page writes and synchronous commits. Authorization connections only go to the writable leader. TLS-verified `/primary` probes require both a running primary and its leader lock; demoted servers' existing routed connections are closed. The router allows ten minutes of SQL traffic inactivity; retain bounded per-operation client deadlines below that limit. Long-running maintenance needs an explicit operator budget and leader-aware connection handling; it must not rely on a thirty-second transport timeout. Old timelines are not automatically deleted to repair a failed rewind. Changing `bootstrap.dcs` after initialization does not change live DCS settings; use an authenticated reviewed Patroni operation and retain the effective-config evidence.

## Backups and acceptance

`archive.py` performs synced, atomic, no-overwrite local WAL archival with a 512 MiB fixture cap. Complete WAL segments, promotion-generated `.partial` files, timeline history and backup-history names are accepted. Identical retries succeed; conflicting contents or budget exhaustion fail. Archives and PostgreSQL WAL must be monitored: an exhausted archive cannot delete unarchived WAL safely, and WAL can consequently grow. This local archive is **not an independent disaster backup**. Do not run an unattended long-lived test cluster without capacity supervision.

Before moving any existing canary data, take a closed/config-consistent backup and verify an isolated restore. For the new fixture, use `pg_basebackup` from an authenticated verified-TLS leader, retain WAL and backup metadata on a host bind, verify with `pg_verifybackup`, then restore into a fresh guarded root with `restore_command`/`recovery_target_time` and a separate namespace/network boundary. Use a copy of the verified backup, never modify the original. Before standalone recovery, remove every copied `recovery_target*` assignment from the cloned PostgreSQL/Patroni configuration, including empty assignments, then explicitly set exactly one desired target and timeline/action. Multiple configured targets can prevent recovery from starting. Keep the restore unable to reach DCS, applications or the live leader. Prove both a base restore and a timestamped PITR marker with acknowledged records before and after the target. Never restore an earlier authorization snapshot into a live fleet: this can revive consumed/revoked credentials. Retain the old canary database until replacement and rollback tests pass.

Record actual observed leader, synchronous standby, etcd voter health, effective DCS settings, certificate verification, memory/OOM counters and disk growth. Test cross-node fresh password/2FA, concurrent one-time consumption, session revocation, event deduplication, collector outage/restart, loss of each data node, quorum loss and recovery. Record every acknowledged marker before failure and verify it after recovery; test ambiguous commits separately. Bound fault injection to this fixture's containers/namespaces. Full Hodus-host-loss acceptance requires independent surviving routes and state, not stopping only its application container.

**Fencing is deliberately off in this fixture.** It does not access or arm `/dev/watchdog`. A paused or isolated former primary has not been proven fenced; neither container failover nor strict replication alone proves split-brain safety. Production requires a separately reviewed, actually tested fail-closed fencing deployment (Patroni watchdog required or equivalent), suitable capacity, restore/PITR and supported single-host/partition acceptance. Watchdogs can reset an entire shared host; prepare the concrete settings and controlled drill before enabling them. Test-only `soft_noboot` is not real fencing. Do not advertise or cut over production active-active routing from this fixture.

Primary references: [Patroni configuration](https://patroni.readthedocs.io/en/latest/yaml_configuration.html), [synchronous modes](https://patroni.readthedocs.io/en/latest/replication_modes.html), [watchdog](https://patroni.readthedocs.io/en/latest/watchdog.html), [etcd TLS](https://etcd.io/docs/v3.6/op-guide/security/), [PostgreSQL continuous archiving](https://www.postgresql.org/docs/18/continuous-archiving.html).

Run `python -m unittest discover -s deploy/ha/state -p 'test_*.py' -v`. Native Linux tests cover synced archive retry/conflict/quota behavior and symlink-resistant directory operations; manifest checks run on all platforms. Real multi-host, TLS, restore, load and fencing tests are separate from these regressions.

CI also runs `sudo python3 deploy/ha/state/test_etcd_gateway.py` on a disposable Docker network. It proves the real HTTP/gRPC gateway can commit/read a marker with separated server/client issuers and rejects missing, server-only and peer certificates as clients. This single-member certificate regression does not prove HA or Tailscale routing; those have separate multi-host acceptance.


## Optional Admin Stats HA observations

`observe.py` is a separate operational process, with no incoming HTTP endpoint. It publishes a bounded, fsynced `ha.json` on an existing host directory. RAuth reads that private report through the optional **control-only** `ha_observation_file` node-config field, for example `/app/data/observations/ha.json`. The app performs no HA network probes on requests and receives no observer TLS key. A failed, missing or stale report affects Stats and diagnostic metrics only; it never changes authentication readiness.

Use `observer.example.json` and `compose.observer.example.yml` as nondeployable examples. Replace the application cluster UUID, expected PostgreSQL system identifier, expected etcd cluster identifier, all three dedicated service IPs and exact output filesystem device with verified private deployment values. The example identifiers are placeholders. The source service IP must be the observer host's own existing dedicated Tailscale service. Probes accept only those three `100.64.0.0/10` addresses, fixed ports and fixed health endpoints. TLS verifies each IP SAN and requires TLS 1.3. Only GET requests and the fixed **read-only** etcd maintenance-status POST are allowed; redirects and proxy environment variables are not used. Each member runs in a child process with a hard 5.5-second deadline, also bounding a stalled response body.

Provision the script, private configuration, curated client leaves and report directory through the exact host UUID guard before creating any path. On Pi3 all of them must remain below `/mnt/usb1/rauth`. Do not mount a Docker socket, CA signing key, PostgreSQL superuser password or REST mutation password. The observer uses the REST **client** leaf and DCS **client** leaf, with their server trust roots. The DCS leaf is a sensitive operator capability in this fixture; it stays solely in the separate producer mount, never in the RAuth app tree. Keep the producer UID 10001 and all configuration/key/report files private; the program may be 0444. Its output directory is 0700, and publication creates mode-0600 regular files atomically. Run RAuth with an additional **read-only bind of the report directory** at its configured path. Preserve that bind through app upgrades. The output directory descriptor is held open and its device must match; no directories are created by the producer and no anonymous persistent volume is allowed. The example explicitly covers the Python image's PostgreSQL VOLUME with bounded tmpfs.

The report records running database roles, lease-aware primary verification, synchronous partners, timeline-aware lag, expected physical identities, etcd voter/leader/database quota and TLS leaf expiry. A primary role string alone is not accepted as a live leader. A missing member leaves quorum potentially available while redundancy is shown as degraded. Reports older than fifteen seconds, read failures or malformed/foreign scope become stale/unavailable; last known samples are retained without being shown as current zeros. Eight bounded `rauth_ha_observation_*` gauges also enter the existing registered diagnostics, with current counts omitted while coverage is unavailable. The central shared counts are observed once, not summed across workers.

This is **observability**, not a fencing attestation. The panel explicitly marks fencing as not observed. A healthy observation does not make the isolated fixture production-ready. Certificate rotation, host boot/UUID supervision, memory/WAL capacity, recovery and the separately approved fencing/host-loss tests remain deployment prerequisites. The test producer deliberately uses `restart: no`; a supervised host startup must recheck its expected filesystem before launch.

### Guarded host supervision

supervise.py supervises only an explicit cohort of existing, image/label-pinned
containers. It never provisions data, initializes PostgreSQL, promotes a replica,
or starts a legacy/rollback authorizer. Every owned container, including its
dedicated Tailscale provider, must have Docker restart policy no. A systemd
unit is the sole boot/recovery owner.

Before each start, the supervisor verifies the live writable filesystem UUID,
free-space and available-memory floors, pinned image/authority, bind sources,
and provider namespace. A local role failure restarts that role; a provider
failure stops its clients before rejoining its namespace. Role startup attempts, including role-local preflight refusals, are limited
to three per role per five minutes. On reaching the limit the supervisor logs
restart_backoff and automatically retries when the oldest attempt leaves that
window. Shared capacity, provider and launcher failures spend no role budget. A verified missing/foreign/read-only
filesystem stops the owned cohort, PostgreSQL first. Capacity/dependency
errors prevent starts without shutting down healthy roles.

Each original entrypoint must be wrapped by cmd/rauth-guard-exec. The supervisor
copies the hash-pinned static launcher into root-owned transient /run tmpfs,
then attests the physical device, filesystem ID, inode and writable flag of
every persistent bind source. The same verified Go binary describes held descriptors for attestation and
verification, avoiding libc or userspace-word-size filesystem-ID conversions.
The container receives read-only launcher and
witness binds. Before executing the original command as PID 1, the launcher
checks the root-owned immutable tmpfs witness, current boot ID, required role
paths and actual mounted identities. This closes the host-check/Docker-bind
race without creating fallback directories. Existing mounts pin their
filesystems; failed verification never executes a writer.

package_supervisor.py produces a JSON source bundle and an uninstalled unit.
The unit pins the complete bundle hash and expected mount/UUID. Its small
isolated Python loader validates storage and held descriptors before executing
any bundle source in memory. Bulk programs and private configuration remain on
the selected data filesystem; on Pi3 they belong below /mnt/usb1/rauth.
Only the generated service and RAM mount units belong in /etc/systemd/system;
/run copies are transient. The dedicated 32MiB tmpfs mount has exec,nosuid,nodev:
several hosts mount /run itself noexec, so using that inherited mount cannot
run the static launcher. The supervisor refuses a noexec RAM mount.
Install root-owned bundles/configuration with mode 0600 and the static launcher
without group/world write permissions. Inspect the generated unit with
systemd-analyze verify before enabling it.

Before rollout, create a private supervisor configuration for the exact node:
storage scope/capacity floors, dedicated service IP, launcher path/hash, explicit
role/name/image-ID/label pins, and only the operational device-field remaps.
Preserve existing original entrypoints, image IDs, binds, environment, limits,
keys and closed spools during the one-time guarded-container migration. Never
replace an old SQL authority with a retained snapshot after new writes.
Migrate one isolated host at a time, preserving quorum and a compatible
rollback description. Dry-run wrong-UUID refusal and test supervised role,
provider and daemon recovery before production activation.

Host supervision does not configure or arm hardware/software watchdogs.
Whole-host fencing and disruptive reset acceptance are separate maintenance
steps. Docker restart policy changes alone do not prove safe failover.

Run portable policy/model tests with
python -m unittest discover -s deploy/ha/state -p 'test_*.py'.
Real Linux acceptance must also cover descriptor identity and refusal before
child execution; Windows model tests cannot establish Linux mount behavior.

Supervisor configuration schema 2 pins every non-guard bind as exact source,
target and writable fields in each role's binds array. Those pins cover the
existing approved data/program directories, including separate Tailscale or
application directories on the same filesystem. A changed source, sibling
prefix, extra bind or writable-mode change prevents startup. The held-descriptor
filesystem checks still apply independently. Pre-release schema 1 configurations
must be regenerated from the reviewed live bind inventory.

For an update, stage the bundle, launcher and schema 2 configuration in a new
private versioned directory below the guarded state root. The generated unit
locates its source bundle next to that configuration. Verify the new unit and
UUID refusal before replacing the OS service unit, reloading systemd and
restarting one owned cohort at a time. Preserve its previous bundle/unit,
current authority and closed spool; do not overwrite a running unit's pinned
bundle path ahead of the unit update.

The generated unit, pinned digest, private supervisor configuration and source
bundle are controlled by the host administrator. The unit belongs to root in
/etc/systemd/system; bundles/configuration require root ownership and private
permissions. Guests receive only read-only RAM guard inputs and cannot replace
the unit or its digest. This protects startup against storage/path mistakes,
untrusted bind substitution and guest modification; an administrator who can
replace both the root-owned unit and its digest remains fully trusted.

Bootstrap failures and escaped supervisor-runtime failures have separate
diagnostics. Runtime diagnostics include the exception type and stack file/line
frames, without exception text, source lines or local values that could contain
private database URLs or credentials.

### Prepared OpenRC counterpart

`package_openrc.py` renders an uninstalled native OpenRC service, the identical
verified loader/bundle and private bounded RAM metadata. It changes no guard
identity/schema or Docker restart policy and installs/starts nothing. See
[OPENRC.md](OPENRC.md) for native namespace, tools, storage, logging and lifecycle
requirements. Portable tests do not prove actual Alpine/OpenRC boot or fencing.

## Automatic leaf renewal (`pki` role)

Physical leaves live 90 days and renew automatically when 30 days or fewer remain. CAs are separate, with a 30-year default, and rotate through an operator overlap rollout. The `pki` role is a supervised container on every node, built from this image (`/usr/local/lib/rauth/pki_renew.py run --config /etc/rauth-pki-renew/config.json`).

- **Issuer: CA master only.** The config's `issuer` section enables it. CA keys are bind-mounted read-only and never leave the master.
  - Serves TLS 1.3 mutual TLS on the node's own service IP. A client must present a `<node>-rest-client` leaf from the REST CA bundle.
  - Never mints new identities. A request must carry an unexpired leaf issued by the authority, whose CN is one of the node's eight purposes and whose SANs are only that node's IP and DNS names. It must also carry a CSR with the same subject and a fresh P-256 key.
  - The renewed leaf copies subject, SAN and extensions.
  - Only one node renews at a time (3-hour lease). A failed rollout blocks every other node until an operator clears `issuer-state.json`.
  - Limit: 32 issuances per node per day. Every issuance is appended to `issued.jsonl` with its SHA-256.
- **Agent: every node.** Checks hourly. Acts only when the cluster shows one running leader and two streaming members at zero lag.
  1. Takes the lease and renews every leaf.
  2. Verifies each result: subject, SAN, EKU, key and chain against the installed trust bundles, and a later expiry.
  3. Backs up the current files under its state directory.
  4. Rewrites the files in place, preserving inode, owner and mode, so bind mounts and host-guard witnesses stay valid.
  5. Writes a fsynced `restart-request.json`.
  
  Any failure before the commit aborts without changes.
- **Host supervisor.** With `pki_renewal.directory` configured, it reads the root-owned private handshake. It restarts etcd, Patroni, router and observer once each, through the normal attested start path.
  - If this node holds the leader, it first moves leadership with a supported switchover to the zero-lag synchronous standby.
  - After every role it waits for a healthy three-member cluster, then writes `restart-done.json`.
  - The agent reports `ok` or `failed` to the issuer. An agent restart resumes the wait.

**Application node identities.** The enrolled `node.crt` used by the private cluster transport also renews 30 days before expiry, through `/v1/identity` when the issuer config has an `identity` section (node CA certificate and key, node name to IP, cluster ID).
- The identity keeps the **same key**, so controller SPKI pins and registry enrollments stay valid.
- The issuer requires the leaf's only IP SAN to belong to the authenticated node and its SPIFFE URI to be inside the cluster.
- An application-only node, such as a worker without a database member, authenticates with its own node identity. It can use only this route, never physical renewal.
- Its restart request names only the `app` group, so the supervisor restarts just the application. That isn't health-gated where no local Patroni exists.

Host-guard role `pki` requires writable `/pki` (node PKI) and `/var/lib/rauth-pki` (handshake and backups). The master additionally mounts the authority read-only. The leaf's EKU decides where it is accepted, so renewal never weakens purpose separation.

## Base backups and archived-WAL retention

`backup.py` runs inside each node's Patroni container (UID 999), which already holds the replication credential, the SQL CA and the archive bind. With an optional supervisor config `"backup": {"interval_hours": 6, "keep": 4}`, the host supervisor starts it as a non-blocking `docker exec`. It runs only while the cluster is healthy, and the first run on each node is staggered.

Each run:
1. Takes a self-contained base backup of the local server over verified TLS (`pg_basebackup -F t -z -X stream --manifest-checksums=SHA256`) into `archive/base/<UTC>.pending`.
2. Verifies it with `pg_verifybackup` and publishes it by atomic rename.
3. Keeps the newest `keep` verified backups.
4. Prunes archived WAL segments that end at or before the oldest kept backup's start LSN. Timeline history files are always kept.

A failed or unverified run removes only its own pending directory and prunes nothing.

`archive.py` stops archiving at 64 GiB of loose WAL or 8 GiB free space. A missing backup therefore keeps WAL in `pg_wal` rather than filling the disk.

These are local, per-node backups for point-in-time recovery inside each site. Off-host disaster recovery is a separate step.
