#!/usr/bin/env python3
"""Native-host OpenRC RAM mount adapter. No data source, Docker or watchdog access."""

import argparse
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
import stat
import subprocess
import sys

RAM = "/run/rauth-ha"
MAX_BYTES = 32 * 1024**2
OPTIONS = "rw,exec,nosuid,nodev,mode=0700,size=32M"


class Fault(RuntimeError):
    """Static diagnostic only; never echo subprocess output or private paths."""


def observation(path):
    try:
        raw = subprocess.check_output([
            "/usr/bin/findmnt", "-J", "--mountpoint", path,
            "-o", "TARGET,FSTYPE,OPTIONS"
        ], stderr=subprocess.DEVNULL, timeout=5)
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            return None
        raise Fault("mount_metadata_unavailable") from None
    if len(raw) > 16384:
        raise Fault("mount_metadata_budget")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise Fault("invalid_mount_metadata")
    rows = document.get("filesystems", [])
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or rows[0].get("target") != path:
        raise Fault("ambiguous_mount")
    return rows[0]


def private_directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise Fault("unsafe_ram_directory")


def verify(row, info, vfs):
    if row is None or row.get("target") != RAM or row.get("fstype") != "tmpfs":
        raise Fault("ram_is_not_dedicated_tmpfs")
    options = set(row.get("options", "").split(","))
    if not {"rw", "nosuid", "nodev"} <= options or {"ro", "noexec"} & options:
        raise Fault("unsafe_ram_mount_flags")
    private_directory(info)
    if not 0 < vfs.f_frsize * vfs.f_blocks <= MAX_BYTES:
        raise Fault("ram_budget_exceeded")
    if vfs.f_flag & (os.ST_RDONLY | os.ST_NOEXEC):
        raise Fault("unsafe_ram_runtime_flags")


def opened(create=False):
    parent = os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Fault("unsafe_run_parent")
        if create:
            try:
                os.mkdir("rauth-ha", 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        fd = os.open("rauth-ha", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            private_directory(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def checked(fd):
    verify(observation(RAM), os.fstat(fd), os.fstatvfs(fd))
    current = os.stat(RAM, follow_symlinks=False)
    private_directory(current)
    held = os.fstat(fd)
    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
        raise Fault("ram_mount_changed")


def no_active_supervisor(fd):
    # OpenRC serializes dependent stops first; also refuse a live native lock.
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise Fault("unsafe_ram_entry")
        if not stat.S_ISDIR(info.st_mode):
            continue
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            private_directory(os.fstat(child))
            try:
                lock = os.open("supervisor.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
            except FileNotFoundError:
                continue
            try:
                inf = os.fstat(lock)
                if not stat.S_ISREG(inf.st_mode) or inf.st_uid != 0 or inf.st_mode & 0o077 or inf.st_nlink != 1:
                    raise Fault("unsafe_supervisor_lock")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Fault("active_supervisor") from None
            finally:
                os.close(lock)
        finally:
            os.close(child)


def manage(action):
    if sys.platform != "linux" or os.geteuid() != 0 or fcntl is None:
        raise Fault("native_linux_host_root_required")
    parent = observation("/run")
    if parent is None or parent.get("fstype") != "tmpfs":
        raise Fault("run_is_not_tmpfs")
    try:
        fd = opened(create=action == "start")
    except FileNotFoundError:
        if action == "stop":
            return
        raise
    try:
        row = observation(RAM)
        if action == "start" and row is None:
            if os.listdir(fd):
                raise Fault("nonempty_unmounted_ram_directory")
            subprocess.run(["/bin/mount", "-t", "tmpfs", "-o", OPTIONS, "tmpfs", RAM],
                           check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.close(fd)
            fd = None
            fd = opened()
        if row is None and action == "stop":
            return
        checked(fd)
        if action == "stop":
            no_active_supervisor(fd)
            os.close(fd)
            fd = None
            # No force/lazy unmount, recursion, cleanup of data or deletion.
            subprocess.run(["/bin/umount", RAM], check=True, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        if fd is not None:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "check", "stop"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        manage(args.action)
    except (Fault, OSError, ValueError, subprocess.SubprocessError):
        print("RAuth private RAM unavailable; inspect native boot metadata", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
