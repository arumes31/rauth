#!/usr/bin/env python3
"""Bounded, private HA observation producer; never an authentication dependency.

Run separately from RAuth. Only the existing host-bound output directory is
writable. TLS client leaves stay in this process, outside the app mount.
"""

import argparse
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
import uuid

LIMIT = 64 * 1024
TAILNET = ipaddress.ip_network("100.64.0.0/10")
NAME = re.compile(r"[a-z][a-z0-9-]{0,30}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")
STOP = False


def bounded_json(raw):
    if not raw or len(raw) > LIMIT:
        raise ValueError("Invalid bounded JSON")
    return json.loads(raw)


def absolute(value):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or str(PurePosixPath(value)) != value
        or ".." in PurePosixPath(value).parts
        or "\\" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("A canonical absolute file path is required")
    return value


def address(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or ip not in TAILNET or str(ip) != value:
        raise ValueError("Only dedicated Tailscale service addresses are accepted")
    return value


def validate(config):
    required = {
        "schema",
        "cluster_id",
        "mode",
        "source_ip",
        "expected_system_id",
        "expected_dcs_cluster_id",
        "output_dir",
        "output_device",
        "members",
        "patroni_ca",
        "patroni_certificate",
        "patroni_key",
        "etcd_ca",
        "etcd_certificate",
        "etcd_key",
    }
    if (
        not isinstance(config, dict)
        or set(config) != required
        or type(config["schema"]) is not int
        or config["schema"] != 1
        or config["mode"] not in ("isolated-test", "production")
    ):
        raise ValueError("Invalid observer configuration")
    if str(uuid.UUID(config["cluster_id"])) != config["cluster_id"]:
        raise ValueError("Invalid application cluster ID")
    for field in ("expected_system_id", "expected_dcs_cluster_id"):
        if (
            not isinstance(config[field], str)
            or not DECIMAL.fullmatch(config[field])
            or int(config[field]) > 2**64 - 1
        ):
            raise ValueError("Expected physical cluster identities are required")
    address(config["source_ip"])
    absolute(config["output_dir"])
    if not re.fullmatch(
        r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)", config["output_device"]
    ):
        raise ValueError("Expected output filesystem device is required")
    for field in (
        "patroni_ca",
        "patroni_certificate",
        "patroni_key",
        "etcd_ca",
        "etcd_certificate",
        "etcd_key",
    ):
        value = absolute(config[field])
        if value == config["output_dir"] or value.startswith(
            config["output_dir"] + "/"
        ):
            raise ValueError("TLS credentials must remain outside the app report bind")
    if not isinstance(config["members"], list) or len(config["members"]) != 3:
        raise ValueError("Exactly three state members are required")
    names, ips = set(), set()
    for member in config["members"]:
        if (
            not isinstance(member, dict)
            or set(member) != {"name", "ip"}
            or not isinstance(member["name"], str)
            or not NAME.fullmatch(member["name"])
            or member["name"] in names
        ):
            raise ValueError("Invalid or duplicate state member")
        ip = address(member["ip"])
        if ip in ips:
            raise ValueError("Duplicate service address")
        names.add(member["name"])
        ips.add(ip)
    if config["source_ip"] not in ips:
        raise ValueError("Observer must use its own state node service namespace")
    return config


def context(config, service):
    ctx = ssl.create_default_context(cafile=config[service + "_ca"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config[service + "_certificate"], config[service + "_key"])
    return ctx


def request(config, member, service, path):
    allowed = {
        "patroni": {"/patroni", "/primary"},
        "etcd": {"/health", "/v3/maintenance/status"},
    }
    if path not in allowed[service]:
        raise ValueError("Unapproved observation endpoint")
    ip = address(member["ip"])
    connection = http.client.HTTPSConnection(
        ip,
        8008 if service == "patroni" else 2379,
        context=context(config, service),
        source_address=(address(config["source_ip"]), 0),
        timeout=1.2,
    )
    try:
        connection.connect()
        expiry = ssl.cert_time_to_seconds(connection.sock.getpeercert()["notAfter"])
        maintenance = path == "/v3/maintenance/status"
        # This whitelisted POST is a read-only etcd maintenance status request.
        connection.request(
            "POST" if maintenance else "GET",
            path,
            body="{}" if maintenance else None,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(LIMIT + 1)
        data = bounded_json(raw)
        if not isinstance(data, dict):
            raise ValueError("Invalid API object")
        return response.status, data, expiry
    finally:
        connection.close()


def number(value, maximum=2**63 - 1):
    if isinstance(value, bool):
        raise ValueError("Invalid numeric observation")
    if isinstance(value, str) and not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("Invalid numeric observation")
    if not isinstance(value, (str, int)):
        raise ValueError("Invalid numeric observation")
    parsed = int(value)
    if parsed < 0 or parsed > maximum:
        raise ValueError("Out-of-range observation")
    return parsed


def unavailable(name, issue="unavailable"):
    return {
        "name": name,
        "database_ready": False,
        "role": "unknown",
        "leader_verified": False,
        "timeline": 0,
        "server_version": 0,
        "sync_replicas": 0,
        "dcs_ready": False,
        "dcs_bytes": 0,
        "dcs_quota_bytes": 0,
        "duration_ms": 0,
        "issue": issue,
    }


def member_probe(config, member):
    started = time.monotonic()
    result = unavailable(member["name"])
    expiries = []
    issues = []
    try:
        status, data, expiry = request(config, member, "patroni", "/patroni")
        expiries.append(expiry)
        identity = str(number(data.get("database_system_identifier"), 2**64 - 1))
        if identity == "0":
            raise ValueError("Missing database identity")
        result["system_id"] = identity
        result["database_ready"] = status == 200 and data.get("state") == "running"
        result["role"] = {
            "master": "primary",
            "primary": "primary",
            "replica": "replica",
        }.get(data.get("role"), "unknown")
        result["timeline"] = number(data.get("timeline", 0), 2**32 - 1)
        result["server_version"] = number(data.get("server_version", 0), 999999)
        if identity != config["expected_system_id"]:
            issues.append("identity_mismatch")
        if not result["database_ready"]:
            issues.append("database_unavailable")
        if result["role"] == "primary":
            code, current, expiry = request(config, member, "patroni", "/primary")
            expiries.append(expiry)
            result["leader_verified"] = (
                code == 200
                and current.get("role") in ("master", "primary")
                and str(current.get("database_system_identifier"))
                == config["expected_system_id"]
            )
            result["sync_replicas"] = min(
                2,
                sum(
                    1
                    for row in data.get("replication", [])
                    if isinstance(row, dict)
                    and row.get("state") == "streaming"
                    and row.get("sync_state") in ("sync", "quorum")
                ),
            )
        xlog = data.get("xlog", {})
        if isinstance(xlog, dict):
            position = (
                xlog.get("location")
                if result["role"] == "primary"
                else xlog.get("replayed_location")
            )
            if position is not None:
                result["_position"] = number(position)
    except Exception:
        result["database_ready"] = False
        result["leader_verified"] = False
        issues.append("database_unavailable")
    try:
        code, health, expiry = request(config, member, "etcd", "/health")
        expiries.append(expiry)
        code_status, data, expiry = request(
            config, member, "etcd", "/v3/maintenance/status"
        )
        expiries.append(expiry)
        cluster = str(number(data.get("header", {}).get("cluster_id"), 2**64 - 1))
        ident = str(number(data.get("header", {}).get("member_id"), 2**64 - 1))
        leader = str(number(data.get("leader"), 2**64 - 1))
        if "0" in (cluster, ident, leader):
            raise ValueError("Missing etcd identity")
        result.update(
            dcs_cluster_id=cluster,
            dcs_member_id=ident,
            dcs_leader_id=leader,
            dcs_bytes=number(data.get("dbSize"), 2**40),
            dcs_quota_bytes=number(data.get("dbSizeQuota"), 2**40),
        )
        result["dcs_ready"] = (
            code == 200
            and code_status == 200
            and health.get("health") in (True, "true")
            and not data.get("errors")
            and result["dcs_quota_bytes"] > 0
            and result["dcs_bytes"] <= result["dcs_quota_bytes"]
        )
        if cluster != config["expected_dcs_cluster_id"]:
            issues.append("identity_mismatch")
        if not result["dcs_ready"]:
            issues.append("dcs_unavailable")
    except Exception:
        result["dcs_ready"] = False
        issues.append("dcs_unavailable")
    if expiries:
        result["certificate_expires_at"] = datetime.datetime.fromtimestamp(
            min(expiries), datetime.timezone.utc
        ).isoformat()
    result["duration_ms"] = min(10000, round((time.monotonic() - started) * 1000))
    result["issue"] = (
        "identity_mismatch"
        if "identity_mismatch" in issues
        else issues[0]
        if issues
        else ""
    )
    return result


def bounded_probe(config, member):
    try:
        child = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--member"],
            input=json.dumps({"config": config, "member": member}),
            capture_output=True,
            text=True,
            timeout=5.5,
        )
        if child.returncode != 0:
            raise ValueError("Member probe failed")
        result = bounded_json(child.stdout.encode())
        if not isinstance(result, dict) or result.get("name") != member["name"]:
            raise ValueError("Unexpected child identity")
        return result
    except Exception:
        # A hard process deadline also bounds a slow TLS peer/body. No untrusted
        # error text, credentials, paths or arbitrary HTTP body enters the report.
        result = unavailable(member["name"])
        result["duration_ms"] = 5500
        return result


def capture(config):
    checked = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        members = list(
            pool.map(lambda member: bounded_probe(config, member), config["members"])
        )
    leaders = [
        row
        for row in members
        if row["leader_verified"]
        and row.get("system_id") == config["expected_system_id"]
        and "_position" in row
    ]
    if len(leaders) == 1:
        leader = leaders[0]
        for row in members:
            if (
                "_position" in row
                and row["timeline"] == leader["timeline"]
                and row.get("system_id") == config["expected_system_id"]
            ):
                row["lag_bytes"] = max(0, leader["_position"] - row["_position"])
    for row in members:
        row.pop("_position", None)
    report = {
        "schema": 1,
        "cluster_id": config["cluster_id"],
        "mode": config["mode"],
        "checked_at": checked,
        "expected_system_id": config["expected_system_id"],
        "expected_dcs_cluster_id": config["expected_dcs_cluster_id"],
        "members": members,
    }
    raw = (json.dumps(report, separators=(",", ":")) + "\n").encode()
    if len(raw) > LIMIT:
        raise ValueError("Report exceeds its bound")
    return raw


def output_directory(config):
    fd = os.open(config["output_dir"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}" != config["output_device"]:
        os.close(fd)
        raise ValueError("Unexpected report filesystem; no output written")
    return fd


def publish(directory, raw):
    if not raw or len(raw) > LIMIT:
        raise ValueError("Invalid report size")
    try:
        old = os.stat("ha.json", dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(old.st_mode):
            raise ValueError("Output must be a regular file")
    except FileNotFoundError:
        pass
    name = ".pending-" + uuid.uuid4().hex
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, "ha.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass


def stop(_signum, _frame):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--member", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.member:
        payload = bounded_json(sys.stdin.buffer.read(LIMIT + 1))
        config = validate(payload["config"])
        if payload["member"] not in config["members"]:
            raise ValueError("Unknown member")
        print(json.dumps(member_probe(config, payload["member"])))
        return
    if not args.config:
        parser.error("--config is required")
    filename = absolute(args.config)
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Configuration must be a regular file")
        config = validate(bounded_json(stream.read(LIMIT + 1)))
    output = output_directory(config)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not STOP:
            publish(output, capture(config))
            if args.once:
                break
            for _ in range(50):
                if STOP:
                    break
                time.sleep(0.1)
    finally:
        os.close(output)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("HA observation producer unavailable", file=sys.stderr)
        raise SystemExit(1)
