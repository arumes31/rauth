#!/usr/bin/env python3
"""Build a hash-pinned in-memory supervisor bundle and its systemd unit."""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zlib

# This small loader lives in the unit. Bulk programs/configuration remain on the
# selected data filesystem. No imports or executable source come from that disk
# until its live UUID and the complete bundle digest have been checked.
RAM_MOUNT_NAME = r"run-rauth\x2dha.mount"
RAM_MOUNT_UNIT = """[Unit]
Description=RAuth transient executable guard metadata

[Mount]
What=tmpfs
Where=/run/rauth-ha
Type=tmpfs
Options=rw,exec,nosuid,nodev,mode=0700,size=32M
"""

BOOTSTRAP = r"""
import hashlib,json,os,stat,subprocess,sys,types
from pathlib import PurePosixPath
def fail():
    raise RuntimeError("verified_host_supervision_unavailable")
def absolute(value):
    path=PurePosixPath(value)
    if not value.startswith("/") or str(path)!=value or ".." in path.parts or "\\" in value:
        fail()
    return path
def opened(path):
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        parts=absolute(path).parts[1:]
        for i,part in enumerate(parts):
            flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
            if i<len(parts)-1:flags|=os.O_DIRECTORY
            child=os.open(part,flags,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise
def mountid(fd):
    with open("/proc/self/fdinfo/"+str(fd)) as source:
        for line in source:
            if line.startswith("mnt_id:"):return int(line.split(":")[1])
    fail()
def observed(mount,uuid):
    result=json.loads(subprocess.check_output(["/usr/bin/findmnt","-J","--mountpoint",mount,"-o","TARGET,UUID,FSTYPE,OPTIONS"],timeout=5))
    rows=result.get("filesystems",[])
    if len(rows)!=1:fail()
    row=rows[0]
    if row.get("target")!=mount or row.get("uuid")!=uuid or row.get("fstype") not in ("ext4","xfs","btrfs","zfs") or "rw" not in row.get("options","").split(","):fail()
def run():
    if sys.platform!="linux" or os.geteuid()!=0:fail()
    bundle,digest,mount,uuid,config=sys.argv[1:]
    observed(mount,uuid)
    anchor=opened(mount)
    fd=None
    try:
        fd=opened(bundle)
        a,f=os.fstat(anchor),os.fstat(fd)
        if not stat.S_ISDIR(a.st_mode) or not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077 or f.st_nlink!=1 or not 0<f.st_size<=524288:fail()
        if a.st_dev!=f.st_dev or mountid(anchor)!=mountid(fd) or os.fstatvfs(fd).f_flag&os.ST_RDONLY:fail()
        body=os.read(fd,524289)
        if hashlib.sha256(body).hexdigest()!=digest:fail()
        observed(mount,uuid)
        current=opened(mount)
        try:
            c=os.fstat(current)
            if (a.st_dev,a.st_ino,mountid(anchor))!=(c.st_dev,c.st_ino,mountid(current)):fail()
        finally:os.close(current)
    finally:
        if fd is not None:os.close(fd)
        os.close(anchor)
    document=json.loads(body)
    if set(document)!={"schema","modules"} or document["schema"]!=1 or set(document["modules"])!={"render","prepare","supervise"}:fail()
    sys.dont_write_bytecode=True
    for name in ("render","prepare","supervise"):
        source=document["modules"][name]
        if not isinstance(source,str):fail()
        module=types.ModuleType(name);module.__file__="<verified-rauth-ha>/"+name+".py"
        sys.modules[name]=module
        exec(compile(source,module.__file__,"exec"),module.__dict__)
    sys.argv=["supervise","--config",config,"--uuid",uuid,"--mount",mount]
    sys.modules["supervise"].main()
try:
    run()
except Exception:
    print("RAuth verified host bootstrap unavailable; inspect pinned storage and unit configuration",file=sys.stderr)
    sys.exit(1)
"""


def absolute(value):
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or str(path) != value
        or ".." in path.parts
        or "\\" in value
        or any(c in value for c in "'\"%\n\r\t ")
    ):
        raise ValueError("Unsafe unit path")
    return path


def build(directory, root, mount, uuid, node, config):
    root, mount, config = absolute(root), absolute(mount), absolute(config)
    if (
        root == mount
        or not root.is_relative_to(mount)
        or not root.name.startswith(("rauth-test-", "rauth-prod-"))
        or not config.is_relative_to(root)
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", node)
        or not re.fullmatch(r"[A-Za-z0-9-]{8,64}", uuid)
    ):
        raise ValueError("Unsafe unit scope")
    body = json.dumps(
        {
            "schema": 1,
            "modules": {
                name: (directory / (name + ".py")).read_text(encoding="utf-8")
                for name in ("render", "prepare", "supervise")
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(body) > 524288:
        raise ValueError("Bundle exceeds loader budget")
    digest = hashlib.sha256(body).hexdigest()
    bundle = config.parent / "supervisor.bundle.json"
    loader = base64.b64encode(zlib.compress(BOOTSTRAP.encode(), 9)).decode()
    command = (
        'import base64,zlib;exec(zlib.decompress(base64.b64decode("' + loader + '")))'
    )
    mount_unit = ""
    if str(mount) != "/":
        escaped = "".join(
            c
            if c.isalnum() or c in "_.:"
            else ("-" if c == "/" else "\\x" + format(ord(c), "02x"))
            for c in str(mount).lstrip("/")
        )
        mount_unit = " " + escaped + ".mount"
    unit = f"""[Unit]
Description=RAuth guarded HA supervision ({node})
Requires=docker.service {RAM_MOUNT_NAME}
After=docker.service {RAM_MOUNT_NAME}
BindsTo=docker.service {RAM_MOUNT_NAME}{mount_unit}
RequiresMountsFor={mount}
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User=root
UMask=0077
ExecStart=/usr/bin/python3 -I -B -c '{command}' {bundle} {digest} {mount} {uuid} {config}
Restart=on-failure
RestartSec=10
TimeoutStopSec=240
KillMode=process
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    return body, unit, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "mount", "uuid", "node", "config", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    body, unit, digest = build(
        Path(__file__).parent, args.root, args.mount, args.uuid, args.node, args.config
    )
    target = Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    (target / RAM_MOUNT_NAME).write_text(RAM_MOUNT_UNIT, encoding="utf-8")
    (target / "supervisor.bundle.json").write_bytes(body)
    (target / ("rauth-ha-" + args.node + ".service")).write_text(unit, encoding="utf-8")
    print(json.dumps({"sha256": digest, "bytes": len(body), "installed": False}))


if __name__ == "__main__":
    main()
