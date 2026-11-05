#!/usr/bin/env python3
"""Verified local base backups with archived-WAL retention.

Runs inside the node's Patroni container (UID 999), which already holds the
replication credential, the SQL CA and the archive bind. The host supervisor
schedules it. Each run:

1. removes stale pending directories left by killed runs, and refuses to start
   unless the archive filesystem has room for the largest retained backup plus
   a reserve;
2. takes a self-contained base backup of the local PostgreSQL (primary or
   standby) with pg_basebackup over verified TLS: tar, gzip, streamed WAL,
   SHA-256 manifest, into <archive>/base/<UTC timestamp>.pending;
3. verifies the files against the manifest with pg_verifybackup and, because
   pg_verifybackup cannot parse WAL inside a tar archive, extracts the streamed
   WAL and parses every manifest WAL range with pg_waldump;
4. records start LSN/timeline/size and publishes the backup by atomic rename;
5. keeps the newest KEEP verified backups and removes older ones;
6. prunes archived WAL segments that end at or before the oldest kept backup's
   start LSN. Timeline history files are always kept.

Before publication, a failed or unverified run removes only its own pending
directory and prunes nothing; retention never runs after a failed run. A
failure after publication leaves the published backup in place. A failure
during retention can leave some old backups or WAL segments already removed.
"""

import argparse
import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile

ARCHIVE = Path("/var/lib/rauth-archive")
SEGMENT = re.compile(r"([0-9A-F]{8})([0-9A-F]{8})([0-9A-F]{8})(\.partial|\.[0-9A-F]{8}\.backup)?\Z")
WAL_SEGMENT_BYTES = 16 * 1024**2
STAMP = re.compile(r"\d{8}T\d{6}Z\Z")
WAL_FILE = re.compile(r"(?:[0-9A-F]{24}(?:\.partial)?|[0-9A-F]{8}\.history)\Z")
# Free space kept on top of the largest retained backup. It matches archive.py's
# FREE_FLOOR, so a backup does not push the shared filesystem below it.
RESERVE = 8 * 1024**3
STALE_PENDING = 6 * 3600
MAX_WAL_FILE = 1024**3


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


def remove_stale_pending(base, now):
    removed = []
    if not base.is_dir():
        return removed
    for entry in base.iterdir():
        if entry.name.endswith(".pending") and now.timestamp() - entry.stat().st_mtime > STALE_PENDING:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return removed


def check_free_space(archive, base, reserve):
    """Refuse a run that could fill the filesystem shared with pg_wal."""
    largest = 0
    for entry in published(base):
        try:
            size = int(json.loads((entry / "backup.json").read_text())["bytes"])
        except (OSError, ValueError, KeyError, TypeError):
            size = sum(f.stat().st_size for f in entry.iterdir() if f.is_file())
        largest = max(largest, size)
    if shutil.disk_usage(archive).free < largest + reserve:
        raise ValueError("Insufficient free space for a base backup")


def extract_wal(source, target):
    """Extract only plain WAL and history files from pg_basebackup's WAL tar."""
    target.mkdir(mode=0o700)
    try:
        _extract_wal(source, target)
    except (tarfile.TarError, EOFError) as exc:
        raise ValueError("Unreadable WAL archive") from exc


def _extract_wal(source, target):
    with tarfile.open(source, "r:gz") as tar:
        for member in tar:
            parts = [p for p in PurePosixPath(member.name).parts if p != "."]
            if member.isdir() and parts in ([], ["archive_status"]):
                continue
            if not member.isfile():
                raise ValueError("Unexpected WAL archive member")
            if len(parts) == 2 and parts[0] == "archive_status":
                continue
            if len(parts) != 1 or not WAL_FILE.fullmatch(parts[0]) or member.size > MAX_WAL_FILE:
                raise ValueError("Unexpected WAL archive member")
            with tar.extractfile(member) as handle, open(target / parts[0], "xb") as out:
                shutil.copyfileobj(handle, out)


def verify_wal(cfg, pending, runner):
    """Parse every manifest WAL range from the streamed WAL with pg_waldump."""
    wal = pending / "wal-check"
    try:
        extract_wal(pending / "pg_wal.tar.gz", wal)
        ranges = json.loads((pending / "backup_manifest").read_text())["WAL-Ranges"]
        if not ranges:
            raise ValueError("Backup manifest has no WAL ranges")
        for r in ranges:
            runner(
                [
                    cfg.get("pg_waldump", "pg_waldump"), "--quiet", "--path=" + str(wal),
                    "--timeline=" + str(int(r["Timeline"])),
                    "--start=" + r["Start-LSN"], "--end=" + r["End-LSN"],
                ],
                check=True, capture_output=True, timeout=cfg.get("timeout", 3600),
            )
    finally:
        shutil.rmtree(wal, ignore_errors=True)
    if wal.exists():
        raise OSError("WAL check directory was not removed")


def run_backup(cfg, now=None, runner=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    runner = runner or subprocess.run
    archive = Path(cfg.get("archive", ARCHIVE))
    base = archive / "base"
    base.mkdir(mode=0o700, exist_ok=True)
    remove_stale_pending(base, now)
    check_free_space(archive, base, int(cfg.get("reserve", RESERVE)))
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
        # -n because pg_verifybackup cannot parse WAL inside a tar archive.
        # verify_wal parses the streamed WAL before the backup counts as verified.
        runner([cfg.get("pg_verifybackup", "pg_verifybackup"), "-n", str(pending)], check=True, capture_output=True, timeout=cfg.get("timeout", 3600))
        verify_wal(cfg, pending, runner)
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
    removed += remove_stale_pending(base, now)
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
