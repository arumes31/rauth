import ast
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import package_openrc
import package_supervisor


def launch_arguments(source):
    tree = ast.parse(source)
    call = next(node.value for node in tree.body
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call))
    return ast.literal_eval(call.args[0]), ast.literal_eval(call.args[1])


class OpenRCPackageTests(unittest.TestCase):
    def args(self):
        return [Path(package_openrc.__file__).parent,
                "/opt/rauth/rauth-prod-worker", "/",
                "11111111-1111-4111-8111-111111111111", "worker-d",
                "/opt/rauth/rauth-prod-worker/version-next/config.json"]

    def test_exact_existing_bundle_and_bootstrap_are_reused(self):
        result = package_openrc.build(*self.args())
        body, systemd, digest = package_supervisor.build(*self.args())
        self.assertEqual(result["bundle"], body)
        self.assertEqual(result["sha256"], digest)
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        launch = result["files"]["etc/rauth-ha/worker-d/launch"][0]
        executable, argv = launch_arguments(launch)
        self.assertEqual(executable, "/usr/bin/python3")
        self.assertNotIn("#!/bin/sh", launch)
        self.assertEqual(launch.splitlines()[0], "#!/usr/bin/python3 -I")
        expected = shlex.split(next(x.removeprefix("ExecStart=") for x in systemd.splitlines()
                                   if x.startswith("ExecStart=")))
        self.assertEqual(argv, expected)
        self.assertEqual(result["bundle_destination"],
                         "/opt/rauth/rauth-prod-worker/version-next/supervisor.bundle.json")
        self.assertEqual(set(json.loads(body)["modules"]), {"render", "prepare", "supervise"})

    def test_loader_argument_transport_executes_inert_payload_only(self):
        with mock.patch.object(package_supervisor, "BOOTSTRAP", "import json,sys; print(json.dumps(sys.argv))"):
            result = package_openrc.build(*self.args())
        launch = result["files"]["etc/rauth-ha/worker-d/launch"][0]
        executable, argv = launch_arguments(launch)
        with mock.patch("os.execv") as execute:
            exec(compile(launch, "generated-launcher", "exec"), {})
        execute.assert_called_once_with(executable, argv)
        completed = subprocess.run([sys.executable, *argv[1:]], capture_output=True,
                                   text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)[1:], argv[5:])

    def test_metacharacters_in_permitted_paths_never_reach_a_shell(self):
        args = self.args()
        args[1] += ";marker`literal`"
        args[-1] = args[1] + "/version-next/config.json"
        with mock.patch.object(package_supervisor, "BOOTSTRAP", "import json,sys; print(json.dumps(sys.argv))"):
            result = package_openrc.build(*args)
        launch = result["files"]["etc/rauth-ha/worker-d/launch"][0]
        executable, argv = launch_arguments(launch)
        with mock.patch("os.execv") as execute:
            exec(compile(launch, "generated-launcher", "exec"), {})
        execute.assert_called_once_with(executable, argv)
        self.assertEqual(argv[-1], args[-1])
        completed = subprocess.run([sys.executable, *argv[1:]], capture_output=True,
                                   text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)[-1], args[-1])

    def test_host_service_dependencies_shutdown_and_respawn_are_bounded(self):
        result = package_openrc.build(*self.args())
        service = result["files"]["etc/init.d/rauth-ha-worker-d"][0]
        self.assertIn('supervisor="supervise-daemon"', service)
        self.assertIn("need docker localmount rauth-ha-ram", service)
        for setting in ["respawn_delay=10", "respawn_max=3", "respawn_period=300",
                        'retry="TERM/300/KILL/5"', 'umask="0077"']:
            self.assertIn(setting, service)
        self.assertIn('command_args=""', service)
        self.assertIn('command_args_foreground=""', service)
        self.assertNotIn("stopgroup=", service)
        self.assertNotIn("docker start", service)
        self.assertNotIn("docker compose", service)
        self.assertNotIn("RestartPolicy", service)
        self.assertNotIn("watchdog", service)
        self.assertNotIn("output_log=", service)  # no unbounded RAM log
        self.assertIn('pidfile="/run/rauth-ha/openrc-worker-d.pid"', service)
        ram = result["files"]["etc/init.d/rauth-ha-ram"][0]
        self.assertIn("need localmount", ram)
        self.assertIn("/etc/rauth-ha/openrc_ram.py start", ram)
        self.assertIn("/etc/rauth-ha/openrc_ram.py stop", ram)

    def test_unsafe_scope_and_environment_paths_are_rejected(self):
        for index, value in [(1, "/other"), (2, "/bad%h"),
                             (3, "uuid\ncommand"), (4, "node;evil"),
                             (5, "/foreign/config.json"),
                             (5, "/opt/rauth/rauth-prod-worker/$HOME/config.json")]:
            args = self.args(); args[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                package_openrc.build(*args)

    def test_incompatible_existing_package_shape_fails_closed(self):
        with mock.patch.object(package_supervisor, "build", return_value=(b"x", "ExecStart=evil\n", "a" * 64)):
            with self.assertRaises(ValueError):
                package_openrc.build(*self.args())

    def test_cli_stages_only_fresh_private_output_and_never_installs(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "stage"
            argv = ["package_openrc", "--root", self.args()[1], "--mount", "/",
                    "--uuid", self.args()[3], "--node", "worker-d",
                    "--config", self.args()[-1], "--output", str(target)]
            with mock.patch.object(sys, "argv", argv), mock.patch("builtins.print"):
                package_openrc.main()
            manifest = json.loads((target / "install-manifest.json").read_text())
            self.assertFalse(manifest["installed"])
            self.assertEqual(manifest["launch_policy"]["OpenRC_command_args"], [])
            self.assertEqual(manifest["launch_policy"]["isolated_shebang"], "/usr/bin/python3 -I")
            self.assertEqual(manifest["bundle_sha256"],
                             hashlib.sha256((target / "supervisor.bundle.json").read_bytes()).hexdigest())
            self.assertTrue((target / "etc/init.d/rauth-ha-worker-d").is_file())
            with mock.patch.object(sys, "argv", argv), self.assertRaises(FileExistsError):
                package_openrc.main()
