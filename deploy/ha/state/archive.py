#!/usr/bin/env python3
"""Local WAL archive. backup.py prunes it behind verified base backups."""

import hashlib
import os
import re
import stat
import sys
import uuid

NAME = re.compile(
    r"(?:[0-9A-F]{24}(?:\.[0-9A-F]{8}\.backup|\.partial)?|[0-9A-F]{8}\.history)\Z"
)
# Hard ceiling for loose archived WAL (base backups live in base/ and are
# bounded by their own retention). Archiving also stops before the filesystem
# drops below FREE_FLOOR. Refused WAL stays in pg_wal on the same filesystem
# and can still fill it, so free space and backup age must be monitored.
LIMIT = 64 * 1024**3
FREE_FLOOR = 8 * 1024**3


def digest(fd):
    result = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        result.update(chunk)
    return result.digest()


def archive(source, name, directory="/var/lib/rauth-archive"):
    if not NAME.fullmatch(name):
        raise ValueError("Invalid archive filename")
    target = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    original = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary = None
    try:
        st = os.fstat(original)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024**2:
            raise ValueError("Invalid WAL source")
        try:
            existing = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=target
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                if not stat.S_ISREG(os.fstat(existing).st_mode) or digest(
                    existing
                ) != digest(original):
                    raise ValueError("Conflicting existing archive file")
                os.fsync(existing)
                os.fsync(target)
                return
            finally:
                os.close(existing)
        used = sum(
            entry.stat(follow_symlinks=False).st_size
            for entry in os.scandir(target)
            if entry.is_file(follow_symlinks=False)
        )
        if used + st.st_size > LIMIT:
            raise ValueError("Archive budget exhausted; take and verify a backup")
        fs = os.statvfs(target)
        if fs.f_bavail * fs.f_frsize - st.st_size < FREE_FLOOR:
            raise ValueError("Archive free-space floor reached")
        temporary = ".pending-" + uuid.uuid4().hex
        out = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=target,
        )
        try:
            while chunk := os.read(original, 1024 * 1024):
                view = memoryview(chunk)
                while view:
                    count = os.write(out, view)
                    if count <= 0:
                        raise OSError("Short WAL archive write")
                    view = view[count:]
            os.fsync(out)
        finally:
            os.close(out)
        # Atomic no-overwrite publication; a concurrent writer cannot replace a WAL.
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=target,
                dst_dir_fd=target,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=target
            )
            try:
                if not stat.S_ISREG(os.fstat(existing).st_mode) or digest(
                    existing
                ) != digest(original):
                    raise ValueError("Conflicting concurrent archive file")
            finally:
                os.close(existing)
        os.unlink(temporary, dir_fd=target)
        temporary = None
        os.fsync(target)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=target)
        os.close(original)
        os.close(target)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("Expected source and archive name")
        archive(sys.argv[1], sys.argv[2])
    except (ValueError, OSError):
        print("Local fixture WAL archive failed", file=sys.stderr)
        sys.exit(1)
