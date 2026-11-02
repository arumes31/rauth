#!/usr/bin/env python3
"""Keep persistent secrets out of Docker environment/arguments and public config."""

import json
import os
from pathlib import Path
import stat


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_mode & 0o077
            or st.st_uid not in (0, os.getuid())
            or st.st_size > 65536
        ):
            raise ValueError("Unsafe private configuration file")
        with os.fdopen(fd, encoding="utf-8", closefd=False) as f:
            return json.load(f)
    finally:
        os.close(fd)


def merge(config, secrets):
    if set(secrets) != {"superuser", "replication", "rewind", "rest"}:
        raise ValueError("Unexpected secret purposes")
    for name, password in secrets.items():
        if (
            not isinstance(password, str)
            or not 32 <= len(password) <= 256
            or any(ord(c) < 33 or ord(c) > 126 for c in password)
        ):
            raise ValueError("Invalid secret")
        if name == "rest":
            config["restapi"]["authentication"] = {
                "username": "rauth_operator",
                "password": password,
            }
            config["ctl"]["authentication"] = {
                "username": "rauth_operator",
                "password": password,
            }
        else:
            config["postgresql"]["authentication"][name]["password"] = password
    return config


def main():
    os.umask(0o077)
    config = merge(
        private_json("/etc/rauth/patroni.json"),
        private_json("/etc/rauth-secrets/patroni-auth.json"),
    )
    path = Path("/run/patroni/patroni.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f)
    os.execv("/opt/patroni/bin/patroni", ["patroni", str(path)])


if __name__ == "__main__":
    main()
