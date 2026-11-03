#!/usr/bin/env python3
"""Render uninstalled OpenRC metadata around the unchanged verified supervisor."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shlex

import package_supervisor


def build(directory, root, mount, uuid, node, config):
    # The systemd builder remains the single definition of source bundle, scope,
    # digest and verified bootstrap. Never duplicate or weaken its loader here.
    body, unit, digest = package_supervisor.build(
        directory, root, mount, uuid, node, config
    )
    starts = [line[len("ExecStart="):] for line in unit.splitlines()
              if line.startswith("ExecStart=")]
    if len(starts) != 1:
        raise ValueError("Unexpected supervisor bootstrap")
    argv = shlex.split(starts[0])
    if argv[:4] != ["/usr/bin/python3", "-I", "-B", "-c"] or len(argv) != 10:
        raise ValueError("Unexpected supervisor bootstrap arguments")
    launcher = (
        "#!/usr/bin/python3 -I\n"
        "# Root-owned boot metadata; argv is literal, never shell-evaluated.\n"
        "import os\n"
        "os.execv(" + repr(argv[0]) + ", " + repr(argv) + ")\n"
    )
    service = f'''#!/sbin/openrc-run
name="RAuth guarded HA supervision ({node})"
description="Own only the exact UUID-verified Docker cohort"
supervisor="supervise-daemon"
command="/etc/rauth-ha/{node}/launch"
command_args=""
command_args_foreground=""
command_user="root:root"
umask="0077"
pidfile="/run/rauth-ha/openrc-{node}.pid"
respawn_delay=10
respawn_max=3
respawn_period=300
# Six possible ordered Docker stops have a 40-second ceiling each.
retry="TERM/300/KILL/5"
output_logger="/usr/bin/logger -t rauth-ha-{node}"
error_logger="/usr/bin/logger -t rauth-ha-{node}"

depend() {{
    need docker localmount rauth-ha-ram
    after bootmisc
}}
'''
    ram_service = '''#!/sbin/openrc-run
name="RAuth private transient guard metadata"
description="Verify the bounded executable witness tmpfs"

depend() {
    need localmount
    after bootmisc
}

start() {
    ebegin "Preparing RAuth private RAM mount"
    /usr/bin/python3 -I -B /etc/rauth-ha/openrc_ram.py start
    eend $?
}

stop() {
    ebegin "Releasing RAuth private RAM mount"
    /usr/bin/python3 -I -B /etc/rauth-ha/openrc_ram.py stop
    eend $?
}
'''
    return {
        "bundle": body,
        "sha256": digest,
        "bundle_destination": str(PurePosixPath(config).parent / "supervisor.bundle.json"),
        "files": {
            f"etc/init.d/rauth-ha-{node}": (service, 0o700),
            "etc/init.d/rauth-ha-ram": (ram_service, 0o700),
            f"etc/rauth-ha/{node}/launch": (launcher, 0o700),
            "etc/rauth-ha/openrc_ram.py": (
                (directory / "openrc_ram.py").read_text(encoding="utf-8"), 0o600
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "mount", "uuid", "node", "config", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = build(Path(__file__).parent, args.root, args.mount, args.uuid,
                   args.node, args.config)
    # Private, fresh operator staging only. Never install/enable/start anything.
    target = Path(args.output)
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    for relative, (text, mode) in result["files"].items():
        path = target / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(text)
        os.chmod(path, mode)
    bundle = target / "supervisor.bundle.json"
    with bundle.open("xb") as output:
        output.write(result["bundle"])
    os.chmod(bundle, 0o600)
    (target / "install-manifest.json").write_text(json.dumps({
        "bundle_destination": result["bundle_destination"],
        "bundle_sha256": result["sha256"],
        "owner": "root:root",
        "installed": False,
        "launch_policy": {
            "OpenRC_command": "/etc/rauth-ha/" + args.node + "/launch",
            "OpenRC_command_args": [],
            "isolated_shebang": "/usr/bin/python3 -I",
            "verified_bootstrap_argv_prefix": ["/usr/bin/python3", "-I", "-B", "-c"],
        },
        "boot_files": {"/" + key: oct(mode) for key, (_, mode) in result["files"].items()},
    }, indent=2) + "\n", encoding="utf-8")
    os.chmod(target / "install-manifest.json", 0o600)
    print(json.dumps({"sha256": result["sha256"], "installed": False}))


if __name__ == "__main__":
    main()
