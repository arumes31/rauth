#!/usr/bin/env python3
"""Verified local base backups with archived-WAL retention.

Runs inside the node's Patroni container (UID 999), which already holds the
replication credential, the SQL CA and the archive bind. The host supervisor
schedules it. Each run:

1. takes a self-contained base backup of the local PostgreSQL (primary or
   standby) with pg_basebackup over verified TLS: tar, gzip, streamed WAL,
   SHA-256 manifest, into <archive>/base/<UTC timestamp>.pending;
2. verifies it with pg_verifybackup, records start LSN/timeline/size, and
   publishes it by atomic rename;
3. keeps the newest KEEP verified backups and removes older ones and stale
   pending directories;
4. prunes archived WAL segments that end at or before the oldest kept backup's
   start LSN. Timeline history files are always kept.

A failed run changes nothing except removing its own pending directory.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ARCHIVE = Path("/var/lib/rauth-archive")
SEGMENT = re.compile(r"([0-9A-F]{8})([0-9A-F]{8})([0-9A-F]{8})(\.partial|\.[0-9A-F]{8}\.backup)?\Z")
WAL_SEGMENT_BYTES = 16 * 1024**2
STAMP = re.compile(r"\d{8}T\d{6}Z\Z")


def lsn_value(text):
    high, low = text.split("/")
    return (int(high, 16) << 32) | int(low, 16)


def segment_end(name, segment_bytes=WAL_SEGMENT_BYTES):
    """Exclusive end LSN covered by a WAL segment file name, or None."""
    m = SEGMENT.fullmatch(name)
    if not m:
        return None
    log, seg = int(m.group(2), 16), int(m.group(3), 16)
    per_log = 0x100000000 // segment_bytes
    return (log * per_log + seg + 1) * segment_bytes


def manifest_start(directory):
    """Start LSN and timeline from a verified backup's manifest."""
    manifest = json.loads((directory / "backup_manifest").read_text())
    ranges = manifest["WAL-Ranges"]
    first = min(ranges, key=lambda r: lsn_value(r["Start-LSN"]))
    return lsn_value(first["Start-LSN"]), first["Start-LSN"], int(first["Timeline"])


def published(base):
    out = []
    if not base.is_dir():
        return out
    for entry in sorted(base.iterdir()):
        if entry.is_dir() and STAMP.fullmatch(entry.name) and (entry / "backup.json").is_file():
            out.append(entry)
    return out


def run_backup(cfg, now=None, runner=subprocess.run):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    archive = Path(cfg.get("archive", ARCHIVE))
    base = archive / "base"
    base.mkdir(mode=0o700, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    pending = base / (stamp + ".pending")
    pending.mkdir(mode=0o700)
    try:
        env = dict(os.environ, PGPASSWORD=cfg["password"], PGSSLMODE="verify-full", PGSSLROOTCERT=cfg["sslrootcert"], PGCONNECT_TIMEOUT="10")
        cmd = [
            cfg.get("pg_basebackup", "pg_basebackup"), "-h", cfg["host"], "-p", str(cfg.get("port", 5432)),
            "-U", cfg["user"], "-D", str(pending), "-F", "t", "-z", "-X", "stream",
            "-c", "fast", "--manifest-checksums=SHA256", "--no-password",
        ]
        runner(cmd, env=env, check=True, capture_output=True, timeout=cfg.get("timeout", 3600))
        runner([cfg.get("pg_verifybackup", "pg_verifybackup"), "-n", str(pending)], check=True, capture_output=True, timeout=cfg.get("timeout", 3600))
        start, start_text, timeline = manifest_start(pending)
        size = sum(f.stat().st_size for f in pending.iterdir() if f.is_file())
        info = {"stamp": stamp, "start_lsn": start_text, "timeline": timeline, "bytes": size, "verified": True}
        fd = os.open(pending / "backup.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, json.dumps(info).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        for f in pending.iterdir():
            with open(f, "rb+") as handle:
                os.fsync(handle.fileno())
        os.rename(pending, base / stamp)
        fsync_dir(base)
        return info
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def fsync_dir(path):
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def retain(cfg, now=None):
    """Keep the newest verified backups and prune WAL they no longer need."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    archive = Path(cfg.get("archive", ARCHIVE))
    base = archive / "base"
    keep = int(cfg.get("keep", 4))
    if keep < 1:
        raise ValueError("keep must be at least one")
    backups = published(base)
    removed = []
    for old in backups[:-keep]:
        shutil.rmtree(old)
        removed.append(old.name)
    kept = backups[-keep:]
    if base.is_dir():
        for entry in base.iterdir():
            if entry.name.endswith(".pending"):
                age = now.timestamp() - entry.stat().st_mtime
                if age > 6 * 3600:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed.append(entry.name)
    pruned = 0
    if kept:
        oldest = min(manifest_start(b)[0] for b in kept)
        for entry in archive.iterdir():
            if not entry.is_file() or entry.name.endswith(".history"):
                continue
            end = segment_end(entry.name)
            if end is not None and end <= oldest:
                entry.unlink()
                pruned += 1
        fsync_dir(archive)
    return {"kept": [b.name for b in kept], "removed": removed, "pruned_segments": pruned}


def load_config(keep):
    """Derive connection settings from the container's own Patroni config."""
    patroni = json.loads(Path("/etc/rauth/patroni.json").read_text())
    secrets = json.loads(Path("/etc/rauth-secrets/patroni-auth.json").read_text())
    return {
        "keep": keep,
        # The node's own IP is a SAN of its SQL server certificate.
        "host": patroni["postgresql"]["connect_address"].split(":")[0],
        "user": patroni["postgresql"]["authentication"]["replication"]["username"],
        "sslrootcert": "/etc/rauth-pki/sql-ca.crt",
        "password": secrets["replication"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=int, default=4)
    args = parser.parse_args()
    os.umask(0o077)
    cfg = load_config(args.keep)
    info = run_backup(cfg)
    print(json.dumps({"backup": info, **retain(cfg)}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(json.dumps({"backup": "failed"}))
        sys.exit(1)
