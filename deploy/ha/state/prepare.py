#!/usr/bin/env python3
"""Verify the actual host filesystem before creating any HA fixture directory."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys

from render import absolute, exact


def validate_expectation(expected):
    exact(expected, ("schema", "mode", "node", "root", "mount", "uuid", "usb", "minimum_free_bytes",
                     "minimum_available_memory", "directories", "sql_hostname", "sql_ip"))
    if type(expected["schema"]) is not int or expected["schema"] != 1 or expected["mode"] != "isolated-test":
        raise ValueError("Not an isolated HA fixture storage manifest")
    mount, root = absolute(expected["mount"]), absolute(expected["root"])
    if root == mount or not root.is_relative_to(mount) or not root.name.startswith("rauth-test-"):
        raise ValueError("Unsafe fixture root")
    if type(expected["usb"]) is not bool or expected["usb"] and (str(mount) != "/mnt/usb1" or not root.is_relative_to("/mnt/usb1/rauth")):
        raise ValueError("USB paths must stay below /mnt/usb1/rauth")
    if not isinstance(expected["uuid"], str) or not expected["uuid"]:
        raise ValueError("Missing expected filesystem UUID")
    if not isinstance(expected["directories"], dict):
        raise ValueError("Invalid directory manifest")
    for name, uid in expected["directories"].items():
        p = PurePosixPath(name)
        if not name or p.is_absolute() or ".." in p.parts or str(p) != name or type(uid) is not int or uid not in (0, 999, 10002, 10003):
            raise ValueError("Invalid directory ownership/path")
    for key, floor in (("minimum_free_bytes", 1024**3), ("minimum_available_memory", 96 * 1024**2)):
        if type(expected[key]) is not int or expected[key] < floor:
            raise ValueError("Unsafe fixture capacity requirement")
    return mount, root


def verify_mount(expected, observed):
    mount, _ = validate_expectation(expected)
    rows = observed.get("filesystems", [])
    if len(rows) != 1:
        raise ValueError("Expected exactly one live filesystem mount")
    row = rows[0]
    if row.get("target") != str(mount) or row.get("uuid") != expected["uuid"] or row.get("fstype") not in ("ext4", "xfs", "btrfs", "zfs") or "rw" not in row.get("options", "").split(","):
        raise ValueError("Expected writable host filesystem UUID is absent")


def open_directory(path, device=None):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute(str(path)).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if device is not None and os.fstat(fd).st_dev != device:
            raise ValueError("Filesystem changed during verification")
        return fd
    except BaseException:
        os.close(fd)
        raise


def ensure_tree(anchor, relative, uid, device):
    fd = os.dup(anchor)
    try:
        parts = PurePosixPath(relative).parts
        for i, part in enumerate(parts):
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            if st.st_dev != device or st.st_mode & 0o077 or st.st_uid not in (0, uid):
                raise ValueError("Unsafe existing fixture directory")
            if i == len(parts) - 1:
                os.fchown(fd, uid, uid)
            os.fsync(fd)
    finally:
        os.close(fd)


def prepare(expected, create=False):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Run storage preflight on the Linux host as root")
    mount, root = validate_expectation(expected)
    observed = json.loads(subprocess.check_output(["findmnt", "--json", "--mountpoint", str(mount), "--output", "TARGET,UUID,FSTYPE,OPTIONS"], encoding="utf-8"))
    verify_mount(expected, observed)
    # Hold the verified filesystem open. Path substitution or an unmount cannot
    # redirect later mkdir calls onto the system disk.
    anchor = open_directory(mount)
    try:
        device = os.fstat(anchor).st_dev
        verify_mount(expected, json.loads(subprocess.check_output(["findmnt", "--json", "--mountpoint", str(mount), "--output", "TARGET,UUID,FSTYPE,OPTIONS"], encoding="utf-8")))
        second = open_directory(mount, device)
        os.close(second)
        vfs = os.fstatvfs(anchor)
        if vfs.f_flag & os.ST_RDONLY or vfs.f_bavail * vfs.f_frsize < expected["minimum_free_bytes"]:
            raise ValueError("Filesystem read-only or lacks headroom")
        memory = {k: int(v.split()[0]) * 1024 for k, v in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
        if memory["MemAvailable"] < expected["minimum_available_memory"]:
            raise ValueError("Insufficient currently available host memory")
        if create:
            relative = root.relative_to(mount)
            # Existing ancestors above the dedicated fixture root are traversed,
            # never chmod/chown'ed (e.g. /opt and /mnt/usb1/rauth).
            parent = anchor
            owned_parent = None
            try:
                for part in relative.parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    if owned_parent is not None:
                        os.close(owned_parent)
                    owned_parent = child
                    parent = child
                    if os.fstat(parent).st_dev != device:
                        raise ValueError("Unexpected nested mount")
                ensure_tree(parent, relative.name, 0, device)
                fixture = os.open(relative.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    for path, uid in expected["directories"].items():
                        ensure_tree(fixture, path, uid, device)
                finally:
                    os.close(fixture)
            finally:
                if owned_parent is not None:
                    os.close(owned_parent)
        return {"node": expected["node"], "storage_verified": True, "created": create, "watchdog_armed": False}
    finally:
        os.close(anchor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expectation", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(json.loads(args.expectation.read_text(encoding="utf-8")), args.create)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        print("HA fixture storage preflight failed; no services started", file=sys.stderr)
        sys.exit(1)
