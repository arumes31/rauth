#!/usr/bin/env python3
"""Render an isolated three-data-node HA fixture. Does not create host paths or start services."""

import argparse
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import sys

DIGEST = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{0,30}\Z")
TAILNET = ipaddress.ip_network("100.64.0.0/10")
PORTS = {"etcd": 2379, "peer": 2380, "postgres": 5432, "rest": 8008, "sql": 6543}


def exact(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(required) - set(optional)
        or set(required) - set(value)
    ):
        raise ValueError("Unexpected or missing manifest fields")


def absolute(value):
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        raise ValueError("An absolute Linux path is required")
    path = PurePosixPath(value)
    if str(path) != value or ".." in path.parts or any(ord(c) < 32 for c in value):
        raise ValueError("Noncanonical host path")
    return path


def validate(manifest):
    exact(manifest, ("schema", "mode", "cluster", "images", "nodes"))
    if (
        type(manifest["schema"]) is not int
        or manifest["schema"] != 1
        or manifest["mode"] != "isolated-test"
    ):
        raise ValueError("Only the isolated-test deployment phase is implemented")
    if (
        not isinstance(manifest["cluster"], str)
        or not NAME.fullmatch(manifest["cluster"])
        or not manifest["cluster"].startswith("rauth-test-")
    ):
        raise ValueError("A distinct rauth-test- cluster name is required")
    exact(manifest["images"], ("postgres", "etcd", "router"))
    if not all(
        isinstance(x, str) and DIGEST.fullmatch(x) for x in manifest["images"].values()
    ):
        raise ValueError("Every image must be pinned by digest")
    nodes = manifest["nodes"]
    if not isinstance(nodes, list) or not 3 <= len(nodes) <= 64:
        raise ValueError("Three state members and at most 64 nodes are required")
    names, ips = set(), set()
    for n in nodes:
        exact(n, ("name", "ip", "state", "root", "mount", "uuid", "usb"))
        if (
            not isinstance(n["name"], str)
            or not NAME.fullmatch(n["name"])
            or n["name"] in names
        ):
            raise ValueError("Unique node names are required")
        ip = ipaddress.ip_address(n["ip"])
        if ip.version != 4 or ip not in TAILNET or str(ip) != n["ip"] or n["ip"] in ips:
            raise ValueError(
                "Unique dedicated Tailscale service IPv4 addresses are required"
            )
        if type(n["state"]) is not bool or type(n["usb"]) is not bool:
            raise ValueError("State and USB flags must be booleans")
        root, mount = absolute(n["root"]), absolute(n["mount"])
        if (
            root == mount
            or not root.is_relative_to(mount)
            or not root.name.startswith("rauth-test-")
        ):
            raise ValueError("Use a separate test root below the expected mount")
        if n["usb"] and (
            mount != PurePosixPath("/mnt/usb1")
            or not root.is_relative_to("/mnt/usb1/rauth")
        ):
            raise ValueError("USB node persistence must stay below /mnt/usb1/rauth")
        if not isinstance(n["uuid"], str) or not re.fullmatch(
            r"[a-zA-Z0-9-]{8,64}", n["uuid"]
        ):
            raise ValueError("Record the expected filesystem UUID before deployment")
        names.add(n["name"])
        ips.add(n["ip"])
    if sum(n["state"] for n in nodes) != 3:
        raise ValueError("Exactly three PostgreSQL/etcd state members are required")
    return manifest


def bind(root, source, target, readonly=False):
    return {
        "type": "bind",
        "source": f"{root}/{source}",
        "target": target,
        "read_only": readonly,
        "bind": {"create_host_path": False},
    }


def service(image, uid, memory):
    return {
        "image": image,
        "user": f"{uid}:{uid}",
        "network_mode": "service:tailscale",
        "restart": "no",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": memory,
        "memswap_limit": memory,
        "pids_limit": 128,
        "stop_grace_period": "40s",
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "5m", "max-file": "2"},
        },
        "tmpfs": [f"/tmp:rw,noexec,nosuid,nodev,size=16m,uid={uid},gid={uid},mode=700"],
    }


def render(manifest, name):
    validate(manifest)
    node = next((n for n in manifest["nodes"] if n["name"] == name), None)
    if node is None:
        raise ValueError("Unknown node")
    states = [n for n in manifest["nodes"] if n["state"]]
    cluster, root, ip = manifest["cluster"], node["root"], node["ip"]
    sql_name = f"{cluster}.sql.rauth.internal"
    # SQL is TCP passthrough; every PostgreSQL server certificate has sql_name.
    # RAuth resolves this logical name to its own namespace's local router.
    haproxy = [
        "global",
        "  maxconn 128",
        "defaults",
        "  mode tcp",
        "  timeout connect 2s",
        "  timeout client 10m",
        "  timeout server 10m",
        "  timeout check 2s",
        "listen writable",
        f"  bind {ip}:6543",
        "  option httpchk GET /primary",
        "  http-check expect status 200",
    ]
    for n in states:
        dns = f"{n['name']}.rest.{cluster}.internal"
        haproxy.append(
            f"  server {n['name']} {n['ip']}:5432 check port 8008 check-ssl check-sni {dns} verify required verifyhost {dns} ca-file /etc/rauth-router/rest-ca.crt crt /etc/rauth-router/health-client.pem inter 1s fall 2 rise 2 on-marked-down shutdown-sessions"
        )
    services = {}
    router = service(manifest["images"]["router"], 10002, "32m")
    router.update(
        {
            "command": ["haproxy", "-W", "-db", "-f", "/etc/haproxy/haproxy.cfg"],
            "volumes": [
                bind(root, "config/haproxy.cfg", "/etc/haproxy/haproxy.cfg", True),
                bind(root, "pki/router", "/etc/rauth-router", True),
            ],
        }
    )
    services["sql-router"] = router
    files = {"config/haproxy.cfg": "\n".join(haproxy) + "\n"}
    dirs = {"config": 0, "pki/router": 10002, "backups": 0}
    if node["state"]:
        etcd = service(manifest["images"]["etcd"], 10003, "128m")
        initial = ",".join(f"{n['name']}=https://{n['ip']}:2380" for n in states)
        etcd["entrypoint"] = ["/usr/local/bin/etcd"]
        etcd["command"] = [
            f"--name={name}",
            "--data-dir=/var/lib/etcd",
            f"--initial-cluster={initial}",
            f"--initial-cluster-token={cluster}",
            "--initial-cluster-state=new",
            f"--listen-client-urls=https://{ip}:2379",
            f"--advertise-client-urls=https://{ip}:2379",
            f"--listen-peer-urls=https://{ip}:2380",
            f"--initial-advertise-peer-urls=https://{ip}:2380",
            "--client-cert-auth=true",
            "--trusted-ca-file=/etc/etcd/client-ca.crt",
            "--cert-file=/etc/etcd/server.crt",
            "--key-file=/etc/etcd/server.key",
            "--client-cert-file=/etc/etcd/loopback.crt",
            "--client-key-file=/etc/etcd/loopback.key",
            "--tls-min-version=TLS1.3",
            "--peer-client-cert-auth=true",
            "--peer-trusted-ca-file=/etc/etcd/peer-ca.crt",
            "--peer-cert-file=/etc/etcd/peer.crt",
            "--peer-key-file=/etc/etcd/peer.key",
            "--quota-backend-bytes=67108864",
            "--auto-compaction-mode=periodic",
            "--auto-compaction-retention=1h",
            "--snapshot-count=1000",
            "--max-wals=3",
            "--max-snapshots=3",
            "--heartbeat-interval=250",
            "--election-timeout=2500",
        ]
        etcd["volumes"] = [
            bind(root, "etcd", "/var/lib/etcd"),
            bind(root, "pki/etcd", "/etc/etcd", True),
        ]
        services["etcd"] = etcd
        patroni = service(manifest["images"]["postgres"], 999, "256m")
        patroni["shm_size"] = "32m"
        patroni["tmpfs"].append(
            "/run/patroni:rw,noexec,nosuid,nodev,size=8m,uid=999,gid=999,mode=700"
        )
        patroni["volumes"] = [
            bind(root, "postgres", "/var/lib/postgresql"),
            bind(root, "wal", "/var/lib/rauth-wal"),
            bind(root, "archive", "/var/lib/rauth-archive"),
            bind(root, "config/patroni.json", "/etc/rauth/patroni.json", True),
            bind(
                root,
                "secrets/patroni-auth.json",
                "/etc/rauth-secrets/patroni-auth.json",
                True,
            ),
            bind(root, "pki/patroni", "/etc/rauth-pki", True),
        ]
        services["patroni"] = patroni
        auth = {
            "superuser": {"username": "postgres"},
            "replication": {"username": "replicator"},
            "rewind": {"username": "rewind"},
        }
        for role in auth.values():
            role.update(
                {"sslmode": "verify-full", "sslrootcert": "/etc/rauth-pki/sql-ca.crt"}
            )
        pg = {
            "listen": f"{ip}:5432",
            "connect_address": f"{ip}:5432",
            "data_dir": "/var/lib/postgresql/18/docker",
            "bin_dir": "/usr/lib/postgresql/18/bin",
            "pgpass": "/run/patroni/pgpass",
            "authentication": auth,
            "use_unix_socket": True,
            "basebackup": [{"waldir": "/var/lib/rauth-wal"}],
            "remove_data_directory_on_rewind_failure": False,
            "remove_data_directory_on_diverged_timelines": False,
        }
        hba = ["local all postgres peer", "hostnossl all all 0.0.0.0/0 reject"]
        for n in states:
            hba += [
                f"hostssl replication replicator {n['ip']}/32 scram-sha-256",
                f"hostssl postgres rewind {n['ip']}/32 scram-sha-256",
                f"hostssl all postgres {n['ip']}/32 scram-sha-256",
            ]
        for n in manifest["nodes"]:
            hba.append(f"hostssl all +rauth_runtime {n['ip']}/32 scram-sha-256")
        params = {
            "ssl": "on",
            "ssl_min_protocol_version": "TLSv1.3",
            "ssl_cert_file": "/etc/rauth-pki/sql-server.crt",
            "ssl_key_file": "/etc/rauth-pki/sql-server.key",
            "ssl_ca_file": "/etc/rauth-pki/sql-ca.crt",
            "password_encryption": "scram-sha-256",
            "fsync": "on",
            "full_page_writes": "on",
            "synchronous_commit": "on",
            "shared_buffers": "32MB",
            "effective_cache_size": "96MB",
            "work_mem": "1MB",
            "maintenance_work_mem": "16MB",
            "autovacuum_work_mem": "8MB",
            "autovacuum_max_workers": 1,
            "max_connections": 64,
            "max_worker_processes": 4,
            "max_parallel_workers": 0,
            "wal_level": "replica",
            "wal_log_hints": "on",
            "max_wal_senders": 8,
            "max_replication_slots": 8,
            "max_wal_size": "128MB",
            "min_wal_size": "32MB",
            "max_slot_wal_keep_size": "128MB",
            "unix_socket_directories": "/run/patroni",
            "logging_collector": "off",
            "archive_mode": "on",
            "archive_timeout": "60s",
            "archive_command": "/opt/patroni/bin/python /usr/local/lib/rauth/archive.py %p %f",
        }
        config = {
            "scope": cluster,
            "namespace": "/rauth-isolated/",
            "name": name,
            "restapi": {
                "listen": f"{ip}:8008",
                "connect_address": f"{ip}:8008",
                "certfile": "/etc/rauth-pki/rest-server.crt",
                "keyfile": "/etc/rauth-pki/rest-server.key",
                "cafile": "/etc/rauth-pki/rest-ca.crt",
                "verify_client": "required",
            },
            "ctl": {
                "cacert": "/etc/rauth-pki/rest-ca.crt",
                "certfile": "/etc/rauth-pki/rest-client.crt",
                "keyfile": "/etc/rauth-pki/rest-client.key",
            },
            "etcd3": {
                "hosts": [f"{n['ip']}:2379" for n in states],
                "protocol": "https",
                "cacert": "/etc/rauth-pki/dcs-ca.crt",
                "cert": "/etc/rauth-pki/dcs-client.crt",
                "key": "/etc/rauth-pki/dcs-client.key",
            },
            "watchdog": {"mode": "off"},
            "bootstrap": {
                "initdb": [
                    "data-checksums",
                    {"encoding": "UTF8"},
                    {"waldir": "/var/lib/rauth-wal"},
                ],
                "dcs": {
                    "ttl": 30,
                    "loop_wait": 5,
                    "retry_timeout": 5,
                    "failsafe_mode": False,
                    "synchronous_mode": True,
                    "synchronous_mode_strict": True,
                    "synchronous_node_count": 1,
                    "maximum_lag_on_failover": 0,
                    "check_timeline": True,
                    "postgresql": {
                        "use_pg_rewind": True,
                        "parameters": params,
                        "pg_hba": hba,
                    },
                },
            },
            "postgresql": pg,
            "tags": {"nofailover": False, "noloadbalance": False, "nosync": False},
        }
        files["config/patroni.json"] = json.dumps(config, indent=2) + "\n"
        dirs.update(
            {
                "etcd": 10003,
                "postgres": 999,
                "wal": 999,
                "archive": 999,
                "secrets": 999,
                "pki/patroni": 999,
                "pki/etcd": 10003,
            }
        )
    files["compose.state.json"] = json.dumps({"services": services}, indent=2) + "\n"
    files["expected-storage.json"] = (
        json.dumps(
            {
                "schema": 1,
                "mode": "isolated-test",
                "node": name,
                "root": root,
                "mount": node["mount"],
                "uuid": node["uuid"],
                "usb": node["usb"],
                "minimum_free_bytes": 20 * 1024**3 if node["state"] else 1024**3,
                "minimum_available_memory": 650 * 1024**2
                if node["state"]
                else 96 * 1024**2,
                "directories": dirs,
                "sql_hostname": sql_name,
                "sql_ip": ip,
            },
            indent=2,
        )
        + "\n"
    )
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--node", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Output is local operator staging, never automatic remote deployment.
    files = render(json.loads(args.manifest.read_text(encoding="utf-8")), args.node)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in files.items():
        path = args.output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as f:
            f.write(content)
        path.chmod(0o600)
    print(
        json.dumps(
            {
                "node": args.node,
                "files": len(files),
                "phase": "isolated-test",
                "deployed": False,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, StopIteration) as error:
        print(f"HA fixture rendering failed ({type(error).__name__})", file=sys.stderr)
        sys.exit(1)
