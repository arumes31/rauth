#!/usr/bin/env python3
"""Root-only host supervisor. Existing owned containers only; no provisioning."""

import argparse
import collections
import contextlib

try:
    import fcntl
except ImportError:  # Non-Linux model tests never start supervision.
    fcntl = None
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

import prepare

LIMIT = 64 * 1024
ROLES = ("tailscale", "etcd", "patroni", "router", "app", "observer", "pki")
STOP_ORDER = ("pki", "patroni", "router", "app", "observer", "etcd", "tailscale")
# Leaf renewal restarts every TLS consumer once, one at a time, leader last.
RENEW_ORDER = ("etcd", "patroni", "router", "observer")
HANDSHAKE_LIMIT = 4096
NAME = re.compile(r"rauth-[a-z0-9][a-z0-9-]{0,80}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
STOP = threading.Event()


# Fixed probes run inside the local Patroni container with its own REST client
# identity. They print bounded JSON; no output reaches logs.
CLUSTER_PROBE = """
import json, ssl, urllib.request
cfg = json.load(open('/etc/rauth/patroni.json'))
ip = cfg['restapi']['connect_address'].split(':')[0]
c = ssl.create_default_context(cafile='/etc/rauth-pki/rest-ca.crt')
c.minimum_version = ssl.TLSVersion.TLSv1_3
c.load_cert_chain('/etc/rauth-pki/rest-client.crt', '/etc/rauth-pki/rest-client.key')
c.check_hostname = False
d = json.load(urllib.request.urlopen('https://%s:8008/cluster' % ip, context=c, timeout=15))
print(json.dumps({'self': cfg['name'], 'members': [
    {'name': m['name'], 'role': m['role'], 'state': m['state'], 'lag': m.get('lag')}
    for m in d['members']]}))
"""
SWITCHOVER_PROBE = """
import base64, json, ssl, sys, urllib.error, urllib.request
leader, candidate = sys.argv[1:3]
cfg = json.load(open('/etc/rauth/patroni.json'))
secret = json.load(open('/etc/rauth-secrets/patroni-auth.json'))['rest']
ip = cfg['restapi']['connect_address'].split(':')[0]
assert cfg['name'] == leader
c = ssl.create_default_context(cafile='/etc/rauth-pki/rest-ca.crt')
c.minimum_version = ssl.TLSVersion.TLSv1_3
c.load_cert_chain('/etc/rauth-pki/rest-client.crt', '/etc/rauth-pki/rest-client.key')
c.check_hostname = False
auth = base64.b64encode(('rauth_operator:' + secret).encode()).decode()
req = urllib.request.Request('https://%s:8008/switchover' % ip, method='POST',
    data=json.dumps({'leader': leader, 'candidate': candidate}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + auth})
try:
    status = urllib.request.urlopen(req, context=c, timeout=45).status
except urllib.error.HTTPError as e:
    status = e.code
print(json.dumps({'status': status}))
"""


class Fault(RuntimeError):
    """Static operator reason; never carry Docker output, URLs or credentials."""


class StorageFault(Fault):
    """The expected storage identity or writability is absent."""


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Fault("invalid_configuration")


def pairs(items):
    result, seen = {}, set()
    for key, value in items:
        folded = key.casefold()
        if folded in seen:
            raise Fault("duplicate_configuration_field")
        seen.add(folded)
        result[key] = value
    return result


def document(raw):
    if not raw or len(raw) > LIMIT:
        raise Fault("invalid_bounded_document")
    return json.loads(raw, object_pairs_hook=pairs)


def absolute(value):
    if not isinstance(value, str) or not value.startswith("/"):
        raise Fault("invalid_absolute_path")
    path = PurePosixPath(value)
    if (
        str(path) != value
        or ".." in path.parts
        or "\\" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise Fault("invalid_absolute_path")
    return path


def validate(config):
    keys = ("schema", "storage", "service_ip", "launcher_file", "launcher_sha256", "roles")
    exact(config, keys + (("pki_renewal",) if "pki_renewal" in config else ()))
    if type(config["schema"]) is not int or config["schema"] != 2:
        raise Fault("invalid_configuration_schema")
    s = config["storage"]
    exact(
        s,
        (
            "node",
            "mode",
            "mount",
            "uuid",
            "root",
            "usb",
            "minimum_free_bytes",
            "minimum_available_memory",
        ),
    )
    mount, root = absolute(s["mount"]), absolute(s["root"])
    prefix = {"isolated-test": "rauth-test-", "production": "rauth-prod-"}.get(
        s["mode"]
    )
    if (
        prefix is None
        or root == mount
        or not root.is_relative_to(mount)
        or not root.name.startswith(prefix)
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", s["node"])
    ):
        raise Fault("invalid_owned_storage_scope")
    if type(s["usb"]) is not bool or (
        s["usb"]
        and (str(mount) != "/mnt/usb1" or not root.is_relative_to("/mnt/usb1/rauth"))
    ):
        raise Fault("invalid_usb_scope")
    if not isinstance(s["uuid"], str) or not re.fullmatch(
        r"[A-Za-z0-9-]{8,64}", s["uuid"]
    ):
        raise Fault("invalid_expected_uuid")
    for key, floor in (
        ("minimum_free_bytes", 1024**3),
        ("minimum_available_memory", 96 * 1024**2),
    ):
        if type(s[key]) is not int or s[key] < floor:
            raise Fault("invalid_capacity_floor")
    address = ipaddress.ip_address(config["service_ip"])
    if (
        address.version != 4
        or address not in ipaddress.ip_network("100.64.0.0/10")
        or str(address) != config["service_ip"]
    ):
        raise Fault("invalid_service_address")
    program = absolute(config["launcher_file"])
    if not program.is_relative_to(root) or not SHA.fullmatch(config["launcher_sha256"]):
        raise Fault("invalid_launcher_pin")
    if "pki_renewal" in config:
        exact(config["pki_renewal"], ("directory",))
        if not absolute(config["pki_renewal"]["directory"]).is_relative_to(root):
            raise Fault("invalid_pki_renewal_directory")
    if not isinstance(config["roles"], list) or not 1 <= len(config["roles"]) <= len(ROLES):
        raise Fault("invalid_cohort")
    names, roles = set(), set()
    for role in config["roles"]:
        exact(role, ("name", "role", "image", "labels", "binds", "remap"))
        if (
            role["role"] not in ROLES
            or role["role"] in roles
            or not NAME.fullmatch(role["name"])
            or role["name"] in names
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", role["image"])
        ):
            raise Fault("invalid_cohort_identity")
        roles.add(role["role"])
        names.add(role["name"])
        if (
            not isinstance(role["labels"], dict)
            or not role["labels"]
            or len(role["labels"]) > 16
            or any(
                not isinstance(k, str)
                or not isinstance(v, str)
                or not k
                or not v
                or len(k) > 256
                or len(v) > 256
                for k, v in role["labels"].items()
            )
        ):
            raise Fault("missing_owned_labels")
        if role["role"] == "app":
            tag = role["labels"].get("org.rauth.state-authority", "")
            if not tag.startswith(
                "isolated-ha-" if s["mode"] == "isolated-test" else "production-ha-"
            ):
                raise Fault("missing_sql_authority_pin")
        if not isinstance(role["binds"], list) or not 1 <= len(role["binds"]) <= 64:
            raise Fault("missing_explicit_bind_pins")
        targets = set()
        for pin in role["binds"]:
            exact(pin, ("source", "target", "writable"))
            source, target = absolute(pin["source"]), absolute(pin["target"])
            if (
                source == PurePosixPath("/")
                or not source.is_relative_to(mount)
                or target == PurePosixPath("/")
                or target.is_relative_to("/guard")
                or type(pin["writable"]) is not bool
                or str(target) in targets
            ):
                raise Fault("invalid_explicit_bind_pin")
            if s["usb"] and not source.is_relative_to("/mnt/usb1/rauth"):
                raise Fault("bind_pin_outside_usb")
            targets.add(str(target))
        if not isinstance(role["remap"], list) or len(role["remap"]) > 2:
            raise Fault("invalid_remap_scope")
        for edit in role["remap"]:
            if not isinstance(edit, dict):
                raise Fault("invalid_remap_document")
            keys = {"kind", "path", "cluster_id"}
            if edit.get("kind") == "node":
                keys |= {"node_id", "database_host"}
            elif edit.get("kind") != "observer":
                raise Fault("invalid_remap_kind")
            exact(edit, keys)
            absolute(edit["path"])
            if s["usb"] and not absolute(edit["path"]).is_relative_to(
                "/mnt/usb1/rauth"
            ):
                raise Fault("remap_outside_usb")
            for key in ("cluster_id", "node_id"):
                if key in edit and str(uuid.UUID(edit[key])) != edit[key]:
                    raise Fault("invalid_remap_identity")
    if "tailscale" not in roles:
        raise Fault("missing_dedicated_provider")
    return config


def observation(mount):
    try:
        raw = subprocess.check_output(
            [
                "findmnt",
                "--json",
                "--mountpoint",
                str(mount),
                "--output",
                "TARGET,UUID,FSTYPE,OPTIONS",
            ],
            timeout=5,
        )
        rows = json.loads(raw)["filesystems"]
        if len(rows) != 1:
            raise Fault("unexpected_mount_count")
        return rows[0]
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            raise StorageFault("expected_mount_absent") from None
        raise Fault("mount_observation_unavailable") from None
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        raise Fault("mount_observation_unavailable") from None


def check_mount(expected, row):
    if (
        row.get("target") != expected["mount"]
        or row.get("uuid") != expected["uuid"]
        or row.get("fstype") not in ("ext4", "xfs", "btrfs", "zfs")
        or "rw" not in row.get("options", "").split(",")
    ):
        raise StorageFault("expected_writable_uuid_absent")


class Storage:
    def __init__(self, expected, capacity=False):
        self.expected, self.capacity = expected, capacity
        self.anchor = self.root = None

    def __enter__(self):
        expected = self.expected
        check_mount(expected, observation(expected["mount"]))
        self.anchor = prepare.open_directory(expected["mount"])
        try:
            self.device = os.fstat(self.anchor).st_dev
            self.mount_id = prepare.mount_identity(self.anchor)
            check_mount(expected, observation(expected["mount"]))
            self.root = prepare.open_directory(
                expected["root"], self.device, self.mount_id
            )
            self.vfs = os.fstatvfs(self.root)
            if self.vfs.f_flag & os.ST_RDONLY:
                raise StorageFault("filesystem_became_readonly")
            if self.capacity:
                memory = {
                    line.split(":", 1)[0]: int(line.split()[1]) * 1024
                    for line in Path("/proc/meminfo").read_text().splitlines()
                    if line.startswith("MemAvailable:")
                }
                if (
                    self.vfs.f_bavail * self.vfs.f_frsize
                    < expected["minimum_free_bytes"]
                    or memory["MemAvailable"] < expected["minimum_available_memory"]
                ):
                    raise Fault("startup_capacity_unavailable")
            final = observation(expected["mount"])
            check_mount(expected, final)
            self.fstype = final["fstype"]
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        for attr in ("root", "anchor"):
            fd = getattr(self, attr)
            if fd is not None:
                os.close(fd)
                setattr(self, attr, None)

    @contextlib.contextmanager
    def source(self, filename):
        path = absolute(str(filename))
        if self.expected["usb"] and not path.is_relative_to("/mnt/usb1/rauth"):
            raise Fault("bind_source_outside_usb")
        parent = prepare.open_directory(path.parent, self.device, self.mount_id)
        fd = None
        try:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent,
            )
            info = os.fstat(fd)
            if (
                info.st_dev != self.device
                or prepare.mount_identity(fd) != self.mount_id
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            ):
                raise Fault("bind_source_identity_mismatch")
            yield fd, parent, path.name, info
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def private(self, filename, owners=(0,), limit=LIMIT):
        with self.source(filename) as (fd, _, _, info):
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in owners
                or info.st_mode & 0o077
                or not 0 < info.st_size <= limit
            ):
                raise Fault("private_file_unavailable")
            raw = os.read(fd, limit + 1)
            if len(raw) > limit:
                raise Fault("private_file_too_large")
            return raw


def atomic(parent, name, body, mode=0o444, owner=(0, 0)):
    temporary = ".pending-" + uuid.uuid4().hex
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=parent,
    )
    try:
        os.fchown(fd, *owner)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(body)
            output.flush()
            os.fsync(fd)
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


class Docker:
    def call(self, args, timeout=15, data=None):
        try:
            result = subprocess.run(
                ["/usr/bin/docker", *args],
                capture_output=True,
                timeout=timeout,
                input=data,
            )
        except (OSError, subprocess.SubprocessError):
            raise Fault("docker_operation_unavailable") from None
        if result.returncode or len(result.stdout) > 1024**2:
            raise Fault("docker_operation_failed")
        return result.stdout

    def inspect(self, name):
        rows = json.loads(self.call(["inspect", name]))
        if len(rows) != 1:
            raise Fault("container_identity_unavailable")
        return rows[0]

    def start(self, ident):
        self.call(["start", ident], 30)

    def patroni(self, ident, probe, *args):
        """Run a fixed probe with the container's own TLS identity."""
        return json.loads(
            self.call(
                ["exec", "-i", ident, "/opt/patroni/bin/python", "-", *args],
                60,
                probe.encode(),
            )
        )

    def stop(self, ident):
        self.call(["stop", "--time", "35", ident], 40)

    def same_network(self, client, provider):
        try:
            return os.readlink(
                "/proc/" + str(client["State"]["Pid"]) + "/ns/net"
            ) == os.readlink("/proc/" + str(provider["State"]["Pid"]) + "/ns/net")
        except OSError:
            raise Fault("network_namespace_unavailable") from None

    def provider_ready(self, ident, address):
        result = json.loads(self.call(["exec", ident, "tailscale", "status", "--json"]))
        return result.get("BackendState") == "Running" and address in result.get(
            "TailscaleIPs", []
        )


def container(role, info, ram, provider=None):
    host, config = info["HostConfig"], info["Config"]
    if (
        info["Name"].lstrip("/") != role["name"]
        or info["Image"] != role["image"]
        or any(
            (config.get("Labels") or {}).get(k) != v for k, v in role["labels"].items()
        )
    ):
        raise Fault("cohort_identity_changed")
    if (
        host.get("Privileged")
        or not host.get("ReadonlyRootfs")
        or host.get("RestartPolicy", {}).get("Name") != "no"
    ):
        raise Fault("unsafe_container_restart_or_privilege")
    expected = ["/guard/exec", "--uuid", ram.uuid, "--role", role["role"], "--"]
    if config.get("Entrypoint", [])[: len(expected)] != expected or len(
        config["Entrypoint"]
    ) <= len(expected):
        raise Fault("unguarded_entrypoint")
    if role["role"] == "app":
        env = dict(item.split("=", 1) for item in config.get("Env", []) if "=" in item)
        if (
            env.get("AUTH_STATE_MODE") != "postgres"
            or env.get("CLUSTER_CONFIG_FILE") != "/app/data/config/node.json"
        ):
            raise Fault("unexpected_authentication_authority")
    if provider is not None and host.get("NetworkMode") not in (
        "container:" + provider["Id"],
        "container:" + provider["Name"].lstrip("/"),
    ):
        raise Fault("provider_namespace_changed")
    pins, mounts = {}, []
    for mount in info["Mounts"]:
        target = mount["Destination"]
        if mount["Type"] == "tmpfs":
            continue
        if mount["Type"] != "bind":
            raise Fault("persistent_volume_not_host_bound")
        if target in ("/guard/exec", "/guard/identity.json"):
            source = str(
                ram.path
                / ("exec" if target == "/guard/exec" else role["role"] + ".json")
            )
            if mount["Source"] != source or mount["RW"]:
                raise Fault("mutable_or_foreign_guard_mount")
            pins[target] = True
        else:
            absolute(target)
            mounts.append(mount)
    if len(pins) != 2 or not mounts:
        raise Fault("missing_guard_bind")
    expected = {(p["source"], p["target"], p["writable"]) for p in role["binds"]}
    observed = {(m["Source"], m["Destination"], m["RW"]) for m in mounts}
    if len(mounts) != len(role["binds"]) or observed != expected:
        raise Fault("persistent_bind_pins_changed")
    return mounts


class RAM:
    def __init__(self, config):
        self.uuid = config["storage"]["uuid"]
        self.path = Path("/run/rauth-ha") / config["storage"]["node"]
        self.fd = None

    def open(self):
        result = (
            subprocess.check_output(
                ["findmnt", "-rn", "-T", "/run", "-o", "FSTYPE"], timeout=5
            )
            .decode()
            .strip()
        )
        if result != "tmpfs":
            raise Fault("run_is_not_tmpfs")
        run = prepare.open_directory("/run")
        try:
            for part in ("rauth-ha", self.path.name):
                try:
                    os.mkdir(part, 0o700, dir_fd=run)
                except FileExistsError:
                    pass
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run
                )
                info = os.fstat(child)
                if info.st_uid != 0 or info.st_mode & 0o077:
                    os.close(child)
                    raise Fault("unsafe_run_directory")
                os.close(run)
                run = child
            if os.fstatvfs(run).f_flag & os.ST_NOEXEC:
                raise Fault("run_requires_executable_tmpfs")
            self.fd = run
            run = None
            return self
        finally:
            if run is not None:
                os.close(run)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def launcher(self, storage, config):
        with storage.source(config["launcher_file"]) as (fd, _, _, info):
            if (
                info.st_uid != 0
                or info.st_mode & 0o022
                or not stat.S_ISREG(info.st_mode)
                or not 0 < info.st_size <= 16 * 1024**2
            ):
                raise Fault("untrusted_launcher")
            with os.fdopen(os.dup(fd), "rb") as source:
                body = source.read(16 * 1024**2 + 1)
            if hashlib.sha256(body).hexdigest() != config["launcher_sha256"]:
                raise Fault("launcher_hash_changed")
            atomic(self.fd, "exec", body, 0o555)

    def attest(self, storage, role, mounts):
        targets = []
        for mount in mounts:
            with storage.source(mount["Source"]) as (fd, _, _, info):
                result = subprocess.run(
                    [str(self.path / "exec"), "--inspect-fd", str(fd)],
                    pass_fds=(fd,),
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode or len(result.stdout) > 1024:
                    raise Fault("source_identity_unavailable")
                identity = document(result.stdout)
                exact(identity, ("device", "fsid", "inode"))
                if any(
                    not isinstance(value, str)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
                    or int(value) >= 2**64
                    for value in identity.values()
                ):
                    raise Fault("invalid_source_identity")
                if identity["device"] != str(info.st_dev) or identity["inode"] != str(
                    info.st_ino
                ):
                    raise Fault("source_identity_changed")
                targets.append(
                    {"path": mount["Destination"], **identity, "writable": mount["RW"]}
                )
        witness = {
            "schema": 1,
            "uuid": self.uuid,
            "role": role["role"],
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "targets": targets,
        }
        body = json.dumps(witness).encode()
        if len(body) > LIMIT:
            raise Fault("witness_budget_exceeded")
        atomic(self.fd, role["role"] + ".json", body)


def remap(storage, role, mounts):
    for edit in role["remap"]:
        path = absolute(edit["path"])
        raw = storage.private(path, owners=(0, 10001))
        config = document(raw)
        if not isinstance(config, dict):
            raise Fault("invalid_remap_document")
        if config.get("cluster_id") != edit["cluster_id"]:
            raise Fault("remap_cluster_changed")
        device = str(os.major(storage.device)) + ":" + str(os.minor(storage.device))
        if edit["kind"] == "node":
            if (
                role["role"] != "app"
                or config.get("node_id") != edit["node_id"]
                or config.get("data_root") != "/app/data"
            ):
                raise Fault("remap_node_changed")
            data = next(
                (
                    absolute(m["Source"])
                    for m in mounts
                    if m["Destination"] == "/app/data"
                ),
                None,
            )
            if data is None or path != data / "config/node.json":
                raise Fault("remap_not_the_mounted_node")
            from urllib.parse import urlsplit, parse_qs

            for filename in config["database_files"].values():
                if not isinstance(filename, str) or not filename.startswith(
                    "/app/data/"
                ):
                    raise Fault("database_file_scope_changed")
                local = data / absolute(filename).relative_to("/app/data")
                dsn = urlsplit(
                    storage.private(local, owners=(0, 10001), limit=8192)
                    .decode()
                    .strip()
                )
                query = parse_qs(dsn.query)
                if (
                    dsn.scheme not in ("postgres", "postgresql")
                    or dsn.hostname != edit["database_host"]
                    or dsn.port != 6543
                    or query.get("sslmode") != ["verify-full"]
                    or query.get("target_session_attrs") != ["read-write"]
                ):
                    raise Fault("database_authority_changed")
            if (
                config.get("mount_device") == device
                and config.get("mount_filesystem") == storage.fstype
            ):
                continue
            config.update(mount_device=device, mount_filesystem=storage.fstype)
        else:
            mounted = next(
                (
                    absolute(m["Source"])
                    for m in mounts
                    if m["Destination"] == "/observer/config.json"
                ),
                None,
            )
            if role["role"] != "observer" or path != mounted:
                raise Fault("remap_not_the_mounted_observer")
            if config.get("output_device") == device:
                continue
            config["output_device"] = device
        with storage.source(path) as (_, parent, name, info):
            # Existing private directory only; retain bytes before the sole operational edit.
            backup = name + ".before-device-" + uuid.uuid4().hex
            atomic(parent, backup, raw, 0o600)
            atomic(
                parent,
                name,
                json.dumps(config, indent=2).encode() + b"\n",
                0o600,
                (info.st_uid, info.st_gid),
            )


class Supervisor:
    def __init__(
        self,
        config,
        docker=None,
        storage=Storage,
        ram=None,
        now=time.monotonic,
        wait=None,
    ):
        self.config, self.docker, self.storage = config, docker or Docker(), storage
        self.ram, self.now = ram or RAM(config), now
        self.wait = wait or STOP.wait
        self.roles = sorted(config["roles"], key=lambda r: ROLES.index(r["role"]))
        self.known, self.attempts, self.events = {}, {}, {}

    def event(self, role, state):
        if self.events.get(role) != state:
            print(
                json.dumps(
                    {
                        "node": self.config["storage"]["node"],
                        "role": role,
                        "state": state,
                    }
                ),
                flush=True,
            )
            self.events[role] = state

    def stop(self, clients_only=False):
        for kind in STOP_ORDER:
            if clients_only and kind == "tailscale":
                continue
            info = self.known.get(kind)
            if info is not None and info["State"]["Running"]:
                try:
                    self.docker.stop(info["Id"])
                except Fault:
                    self.event(kind, "stop_failed")
                    continue
                info["State"]["Running"] = False
                self.event(kind, "stopped")

    def budget(self, kind):
        attempts = self.attempts.setdefault(kind, collections.deque())
        now = self.now()
        while attempts and attempts[0] <= now - 300:
            attempts.popleft()
        if len(attempts) >= 3:
            self.event(kind, "restart_backoff")
            return False
        return True

    def inspect(self, tolerate_role_failure=False):
        # The dedicated provider is a shared dependency. Other metadata faults
        # isolate that role while retaining positively owned IDs for safe stop.
        provider_role = self.roles[0]
        provider = self.docker.inspect(provider_role["name"])
        container(provider_role, provider, self.ram)
        previous = self.known.get("tailscale")
        if previous is not None and previous["Id"] != provider["Id"]:
            self.stop(clients_only=True)
        self.known["tailscale"] = provider
        self.available = {"tailscale"}
        self.inspect_failed = False
        for role in self.roles[1:]:
            kind = role["role"]
            try:
                info = self.docker.inspect(role["name"])
                container(role, info, self.ram, provider)
                self.known[kind] = info
                if (
                    info["State"]["Running"]
                    and provider["State"]["Running"]
                    and not self.docker.same_network(info, provider)
                ):
                    self.docker.stop(info["Id"])
                    info["State"]["Running"] = False
                self.available.add(kind)
            except StorageFault:
                raise
            except (
                Fault,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                subprocess.SubprocessError,
            ):
                self.inspect_failed = True
                self.event(kind, "metadata_unavailable")
        if self.inspect_failed and not tolerate_role_failure:
            raise Fault("role_metadata_unavailable")
        return provider

    def tick(self):
        with self.storage(self.config["storage"]):
            provider = self.inspect(tolerate_role_failure=True)
            failed = self.inspect_failed
            if not provider["State"]["Running"]:
                self.stop(clients_only=True)
            for role in self.roles:
                kind = role["role"]
                if kind not in self.available:
                    continue
                info = self.known[kind]
                if info["State"]["Running"]:
                    self.event(kind, "running")
                    continue
                if kind != "tailscale" and not self.docker.provider_ready(
                    provider["Id"], self.config["service_ip"]
                ):
                    self.event(kind, "provider_unavailable")
                    continue
                if not self.budget(kind):
                    continue
                with self.storage(self.config["storage"], capacity=True) as storage:
                    try:
                        mounts = container(
                            role,
                            info,
                            self.ram,
                            None if kind == "tailscale" else provider,
                        )
                        remap(storage, role, mounts)
                    except StorageFault:
                        raise
                    except (
                        Fault,
                        ValueError,
                        TypeError,
                        KeyError,
                        AttributeError,
                        OSError,
                        subprocess.SubprocessError,
                    ):
                        self.attempts[kind].append(self.now())
                        self.event(kind, "preflight_failed")
                        failed = True
                        continue
                    # Capacity and the common trusted executable are dependencies,
                    # so their failures must not consume any role's retry budget.
                    self.ram.launcher(storage, self.config)
                    try:
                        self.ram.attest(storage, role, mounts)
                    except StorageFault:
                        raise
                    except (
                        Fault,
                        ValueError,
                        TypeError,
                        KeyError,
                        AttributeError,
                        OSError,
                        subprocess.SubprocessError,
                    ):
                        self.attempts[kind].append(self.now())
                        self.event(kind, "preflight_failed")
                        failed = True
                        continue
                    self.attempts[kind].append(self.now())
                    self.docker.start(info["Id"])
                    latest = self.docker.inspect(role["name"])
                    container(
                        role,
                        latest,
                        self.ram,
                        None if kind == "tailscale" else provider,
                    )
                    self.known[kind] = latest
                    self.event(
                        kind,
                        "started" if latest["State"]["Running"] else "start_failed",
                    )
                    if kind == "tailscale":
                        provider = latest
            if failed:
                raise Fault("role_preflight_failed")

    # ------------------------------------------------------------ leaf renewal

    def handshake(self, name):
        directory = self.config["pki_renewal"]["directory"]
        try:
            fd = os.open(os.path.join(directory, name), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != 0
                or st.st_mode & 0o077
                or st.st_size > HANDSHAKE_LIMIT
            ):
                raise Fault("unsafe_renewal_handshake")
            value = document(os.read(fd, HANDSHAKE_LIMIT + 1))
        except ValueError:
            raise Fault("invalid_renewal_handshake") from None
        finally:
            os.close(fd)
        if not isinstance(value, dict) or type(value.get("generation")) is not int:
            raise Fault("invalid_renewal_handshake")
        return value

    def finish_renewal(self, generation, result):
        fd = os.open(
            self.config["pki_renewal"]["directory"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            body = json.dumps({"generation": generation, "result": result}).encode()
            atomic(fd, "restart-done.json", body, mode=0o600)
        finally:
            os.close(fd)

    def cluster(self):
        info = self.known.get("patroni")
        if info is None or not info["State"]["Running"]:
            raise Fault("patroni_unavailable")
        view = self.docker.patroni(info["Id"], CLUSTER_PROBE)
        return view["self"], view["members"]

    @staticmethod
    def healthy(members):
        leaders = [
            m for m in members if m["role"] == "leader" and m["state"] == "running"
        ]
        others = [m for m in members if m["role"] != "leader"]
        return (
            len(members) == 3
            and len(leaders) == 1
            and all(
                m["state"] == "streaming" and m["lag"] in (0, None) for m in others
            )
        )

    def cluster_healthy(self):
        try:
            return self.healthy(self.cluster()[1])
        except (Fault, ValueError, KeyError, TypeError):
            return False

    def await_healthy(self, attempts=30):
        for _ in range(attempts):
            if self.cluster_healthy():
                return
            self.wait(6)
        raise Fault("cluster_not_healthy_after_restart")

    def step_down(self):
        me, members = self.cluster()
        if not any(m["name"] == me and m["role"] == "leader" for m in members):
            return
        candidates = [
            m["name"]
            for m in members
            if m["role"] == "sync_standby"
            and m["state"] == "streaming"
            and m["lag"] == 0
        ]
        if not candidates:
            raise Fault("no_switchover_candidate")
        # 503 means Patroni could not confirm in time; the outcome is polled.
        self.docker.patroni(
            self.known["patroni"]["Id"], SWITCHOVER_PROBE, me, candidates[0]
        )
        for _ in range(30):
            self.wait(4)
            try:
                me, members = self.cluster()
            except (Fault, ValueError, KeyError, TypeError):
                continue
            if self.healthy(members) and not any(
                m["name"] == me and m["role"] == "leader" for m in members
            ):
                self.event("patroni", "renewal_switchover")
                return
        raise Fault("switchover_not_confirmed")

    def restart_for_renewal(self, kind):
        self.docker.stop(self.known[kind]["Id"])
        self.known[kind]["State"]["Running"] = False
        for _ in range(36):
            try:
                self.tick()
            except Fault:
                pass
            info = self.known.get(kind)
            if info is not None and info["State"]["Running"]:
                return
            self.wait(5)
        raise Fault("renewal_restart_failed")

    def renewal(self):
        """Apply a committed leaf renewal: rolling restart, leader last."""
        if "pki_renewal" not in self.config:
            return
        request = self.handshake("restart-request.json")
        if request is None:
            return
        done = self.handshake("restart-done.json")
        if done is not None and done["generation"] == request["generation"]:
            return
        groups = request.get("roles", ["physical"])
        if not isinstance(groups, list) or not groups or not set(groups) <= {"physical", "app"}:
            self.finish_renewal(request["generation"], "failed")
            self.event("pki", "renewal_invalid_request")
            return
        kinds = (RENEW_ORDER if "physical" in groups else ()) + (("app",) if "app" in groups else ())
        # Application-only nodes have no local database cluster to gate on.
        gated = "patroni" in self.available
        if gated and not self.cluster_healthy():
            self.event("pki", "renewal_waiting_for_healthy_cluster")
            return
        result = "ok"
        try:
            for kind in kinds:
                if kind not in self.available:
                    continue
                if kind == "patroni":
                    self.step_down()
                self.restart_for_renewal(kind)
                if gated:
                    self.await_healthy()
                self.event(kind, "renewal_restarted")
        except Fault:
            result = "failed"
        self.finish_renewal(request["generation"], result)
        self.event("pki", "renewal_" + result)

    def run(self, once=False):
        try:
            while not STOP.is_set():
                try:
                    self.tick()
                    if not once:
                        self.renewal()
                except StorageFault:
                    self.event("supervisor", "expected_storage_unavailable")
                    self.stop()
                    if once:
                        raise Fault("supervisor_preflight_failed") from None
                except (
                    Fault,
                    TypeError,
                    AttributeError,
                    ValueError,
                    KeyError,
                    OSError,
                    subprocess.SubprocessError,
                ):
                    self.event("supervisor", "dependency_or_role_unavailable")
                    if once:
                        raise Fault("supervisor_preflight_failed") from None
                if once:
                    return
                STOP.wait(5)
        finally:
            if not once:
                self.stop()
            self.ram.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--uuid", required=True)
    parser.add_argument("--mount", required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Fault("linux_host_root_required")
    minimal = {"mount": args.mount, "uuid": args.uuid}
    check_mount(minimal, observation(args.mount))
    # No configuration/program directory is created by startup.
    mount = prepare.open_directory(args.mount)
    try:
        device, ident = os.fstat(mount).st_dev, prepare.mount_identity(mount)
        filename = absolute(args.config)
        parent = prepare.open_directory(filename.parent, device, ident)
        try:
            fd = os.open(
                filename.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent,
            )
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & 0o077
                    or not 0 < info.st_size <= LIMIT
                ):
                    raise Fault("private_supervisor_configuration_required")
                if os.fstat(fd).st_dev != device or prepare.mount_identity(fd) != ident:
                    raise Fault("configuration_mount_changed")
                config = validate(document(os.read(fd, LIMIT + 1)))
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    finally:
        os.close(mount)
    if (
        config["storage"]["uuid"] != args.uuid
        or config["storage"]["mount"] != args.mount
    ):
        raise Fault("bootstrap_scope_changed")
    if not filename.is_relative_to(absolute(config["storage"]["root"])):
        raise Fault("configuration_outside_owned_root")
    with Storage(config["storage"], capacity=True):
        if args.inspect_only:
            print(
                json.dumps(
                    {
                        "node": config["storage"]["node"],
                        "storage_verified": True,
                        "starts": 0,
                    }
                )
            )
            return
        ram = RAM(config).open()
    lock = None
    try:
        lock = os.open(
            "supervisor.lock",
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=ram.fd,
        )
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise Fault("unsafe_supervisor_lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: STOP.set())
        Supervisor(config, ram=ram).run()
    finally:
        if lock is not None:
            os.close(lock)
        ram.close()


if __name__ == "__main__":
    try:
        main()
    except (
        Fault,
        ValueError,
        TypeError,
        OSError,
        KeyError,
        subprocess.SubprocessError,
    ):
        print(
            "RAuth host supervision unavailable; inspect verified configuration and host storage",
            file=sys.stderr,
        )
        sys.exit(1)
