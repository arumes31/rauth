# OpenRC source adapter (uninstalled)

`package_openrc.py` is a renderer, not an installer. It leaves the existing
`package_supervisor.BOOTSTRAP`, bundle schema 1, supervisor schema 2, `prepare.py`,
`supervise.py` and guard-exec identities unchanged. All bulk source/private data
stays on the exact verified data filesystem. Native host supervision is the sole
boot/recovery owner; every owned Docker role retains `restart: no`, its own
Tailscale namespace and exact image/authority/bind pins. No persistent anonymous
volumes or shared NPM-network attachment are introduced.

The generated launcher contains the exact existing UUID/held-FD/SHA bootstrap as
root-owned Python boot metadata. Literal os.execv argv never passes through a
shell or sources a data-disk program. The fixed OpenRC command has explicit
empty command_args/command_args_foreground. The launcher isolated shebang is
`#!/usr/bin/python3 -I`; its execv target is `/usr/bin/python3 -I -B -c` with the
unchanged verified bootstrap argv. The staging manifest records this policy. OpenRC supervise-daemon
owns the native PID/restart while the foreground Python supervisor owns Docker
cohort recovery. Native respawn is3 failures/300s with 10s delay; existing role
budgets remain separate. TERM gets 300s before boundedKILL: six possible ordered
Docker stops can consume 40s each. No process-group kill is requested.

## Private staging only

Use the same `--root`, `--mount`, `--uuid`, `--node`, `--config` arguments as
`package_supervisor.py`, and a new `--output` directory. No real deployment values
or credentials are provided here. The private install manifest records:

- `supervisor.bundle.json`: the verified config's versioned bundle destination,
  root:root, mode 0600.
- `etc/init.d/rauth-ha-NODE` and `etc/init.d/rauth-ha-ram`: root-owned mode 0700.
- `etc/rauth-ha/NODE/launch`: root-owned mode 0700 pinned OS launcher.
- `etc/rauth-ha/openrc_ram.py`: root-owned mode 0600 small RAM-management metadata.

Nothing installs, enables, mounts or starts during rendering. The separately
reviewed installer must use held/no-follow destination descriptors, exact live
UUID and approved versioned pins. Do not replace a running unit's source data.
Common RAM files must match the accepted installed version before adding another
cohort; existing parents/unrelated services must not be changed.

## Native boundary and prerequisites

The inspected OpenRC target is Linux/amd64, BusyBox PID1/OpenRC, Python3.14 and cgroupv2 with
cgroupfs. Verify installed OpenRC version, supervise-daemon/openrc-run, Docker,
`/usr/bin/logger`, native mount/umount and util-linux `/usr/bin/findmnt` JSON/UUID
support. BusyBox tool names alone are insufficient. Use an accepted bounded
native syslog service; never write unbounded logs into the 32 MiB witness mount.

The RAM adapter requires native host root and `/run` tmpfs. It verifies a private
root-owned nonsymlink `/run/rauth-ha`, dedicated tmpfs <=32 MiB, executable with
nosuid/nodev. Foreign, readonly, noexec, oversized or nonprivate mounts fail.
A nonempty unmounted directory is not hidden. OpenRC dependency stop precedes
RAM release; live supervisor locks refuse unmount. Only ordinary umount is used;
busy mounts remain failures, with no force/lazy detach or recursive cleanup.
The unchanged supervisor verifies exact data UUID and witnesses before starts.

An agent chroot is not native host lifecycle dispatch: OpenRC's child inherits
caller namespaces. A separately approved bounded host mount/PID(/network where
needed) namespace installer or actual host-init boot dispatch may be required.
Normal root mount/control rights belong only to the scoped installer/native
service; apps retain all capabilities dropped and no Docker socket. No permanent
privileged helper or host reboot is proposed or authorized here.

Systemd hosts retain the systemd renderer. A capped DBus client exposes only public
host libraries/busctl/socket; the real host job must verify live UUID, heldFD and
SHA before running scoped staged code. Client reachability is not installation
acceptance. Keep real prefixes, identities and deployment evidence private.

## Tests and remaining acceptance

Portable tests prove loader/bundle equality, literal argument transport, scope
refusal, fresh staging, lifecycle rendering and mocked RAM safety. They never
mount storage or call live Docker. Keep existing loader/supervisor regressions
green. Local source/argument/policy review complements those tests; it does not
replace native host acceptance.

Before enabling: shell/OpenRC validation and actual native Alpine start/status,
PID tracking/TERM stop/respawn limits, Docker daemon loss/recovery, provider/client
order, exact wrongUUID refusal before Docker starts, tmpfs flags/budget, cgroup
limits and exact binds/authority. Dependency ordering is not assumed to reproduce
systemd dynamic BindsTo semantics; prove behavior with native Docker supervision.
Do not create fake OpenRC boot markers to bypass chroot detection. Windows model
tests are not Linux mount, boot or fencing acceptance.

Roll out one owned cohort/replica at a time, preserving quorum, previous boot
metadata/bundle, current authority and closed event spool. Rollback never restores
an old SQL/Redis authorization snapshot after writes. Watchdogs, host resets,
production authority and NPM route changes remain separate accepted operations.

Primary references: [openrc-run](https://raw.githubusercontent.com/OpenRC/openrc/master/man/openrc-run.8),
[supervise-daemon](https://raw.githubusercontent.com/OpenRC/openrc/master/man/supervise-daemon.8).

### Failure-boundary review

A normal service stop signals the foreground Python supervisor, whose existing
finally block attempts ordered cohort stop. That is different from hard death.
SIGKILL cannot execute Python cleanup; Docker restart=no does not stop containers
already running. Loss of the OpenRC manager itself is not a demonstrated cohort
stop trigger, and its dependency graph is not systemd BindsTo. Docker API loss is
handled by the unchanged supervisor as dependency unavailability, not proof that
containers stopped. RAM lock refusal and plain umount do not establish that all
Docker clients have terminated. Native fault tests and any additional approved
outer-ownership mechanism are therefore required before activation; this adapter
must not be advertised as manager-loss fencing.

Reference inspected for supervision failure behavior:
[OpenRC supervise-daemon source](https://raw.githubusercontent.com/OpenRC/openrc/master/src/supervise-daemon/supervise-daemon.c).
