# OpenRC counterpart for verified host supervision

Source-only preparation, uncommitted. No host changes, helper creation, service start, reset, PR or push.

The requested implementation is a native OpenRC wrapper around the existing `package_supervisor.BOOTSTRAP` and unchanged `supervise.py` CLI/schema2. The same source bundle/digest and live mount UUID/held-FD checks run before any data-disk source is executed. `prepare.py`, guard-exec and identity schemas stay unchanged. All owned Docker roles retain restart=no, exact bind/image/authority pins and their own Tailscale provider.

## Approaches

1. **Native OpenRC lifecycle adapter (recommended):** render a root-owned OpenRC supervised service and small boot-owned launcher, plus an independent bounded executable tmpfs service. Reuse the exact existing loader and foreground supervisor. This fits the observed Alpine/BusyBox/OpenRC host without replacing its init.
2. Installing systemd on Alpine changes the host lifecycle and maintenance scope; it is unnecessary for an init adapter.
3. Docker autorestart or a container-owned supervisor violates the existing boot/UUID ownership boundary and is excluded.

Only the first approach fits the provided constraints. No new security schema or permanent guest privilege is proposed.

## Files and lifecycle

Add `deploy/ha/state/package_openrc.py` and focused portable tests/docs. It calls the existing package builder for the unchanged bundle and bootstrap command. Rendered artifacts are private staging output only:

- An OpenRC cohort service using `supervise-daemon`, depending on Docker, local mounts and the RAM service. It runs the original loader in foreground, has bounded respawn attempts/delay, and grants enough TERM time for the original ordered Docker stop. No shell command is sourced from the selected data disk.
- A root-owned small launcher in `/etc/rauth-ha` containing the same compressed verified loader/pins as systemd currently carries.
- A root-owned RAM service/adapter for `/run/rauth-ha`, verifying a private root-owned non-symlink path and an exact tmpfs with exec,nosuid,nodev and <=32MiB. It refuses foreign or unsafe existing mounts; ordinary unmount only after dependent cohorts stop, never forced/lazy unmount. `/run` itself must be tmpfs as the existing supervisor requires.

The supervisor remains responsible for role retries, scope/bind validation, witness publication, provider-client ordering, storage refusal and cohort stop. OpenRC does not recreate containers or initialize databases.

## Prerequisites and acceptance

Massiv has Python3.14 and OpenRC tools but still needs proof of native host mount/PID execution and util-linux `findmnt` JSON support at `/usr/bin/findmnt`. A chroot-only command is not a native process-management bridge: OpenRC starts its child in the caller namespaces, unlike Oracle's host systemd broker. A scoped installer may therefore need a separately approved bounded host-namespace entry path. No such helper/job is executed here.

Oracle uses the existing systemd generator. A future capped DBus dispatch client can request a bounded root-owned native job after AppArmor policy is explicitly handled; its client has no data/PKI write authority beyond approved scoped installation. The loader still verifies exact live UUID + held descriptors + SHA before running the job payload. Client library exposure is not native-job acceptance.

Portable tests will prove exact loader reuse, argument quoting, path injection refusal, dependency/stop/respawn rendering and wrong/foreign RAM mount refusal under mocks. Existing package/supervisor tests run unchanged. Native Alpine/OpenRC start/stop, daemon loss, PID tracking, tmpfs flags, UUID refusal before Docker starts and boot recovery remain explicit future host acceptance. No current acceptance is inferred from Windows model tests.
