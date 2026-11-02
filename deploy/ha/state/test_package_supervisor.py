import base64
import hashlib
import json
from pathlib import Path
import shlex
import unittest
import zlib
import subprocess
import sys
from unittest import mock

import package_supervisor


class PackageTests(unittest.TestCase):
    def args(self):
        return [
            Path(package_supervisor.__file__).parent,
            "/mnt/usb1/rauth/rauth-test-state",
            "/mnt/usb1",
            "11111111-1111-4111-8111-111111111111",
            "state-c",
            "/mnt/usb1/rauth/rauth-test-state/supervision/config.json",
        ]

    def test_pinned_bundle_embeds_current_modules_and_no_disk_imports(self):
        body, unit, digest = package_supervisor.build(*self.args())
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        document = json.loads(body)
        for name, source in document["modules"].items():
            self.assertEqual(source, (self.args()[0] / (name + ".py")).read_text())
            compile(source, name + ".py", "exec")
        command = next(
            line.removeprefix("ExecStart=")
            for line in unit.splitlines()
            if line.startswith("ExecStart=")
        )
        argv = shlex.split(command)
        self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-c"])
        self.assertIn(
            base64.b64encode(
                zlib.compress(package_supervisor.BOOTSTRAP.encode(), 9)
            ).decode(),
            argv[4],
        )
        self.assertIn(digest, argv)
        self.assertIn("RequiresMountsFor=/mnt/usb1", unit)
        self.assertIn(
            "BindsTo=docker.service "
            + package_supervisor.RAM_MOUNT_NAME
            + " mnt-usb1.mount",
            unit,
        )
        self.assertNotIn("watchdog", unit.lower())
        compile(package_supervisor.BOOTSTRAP, "bootstrap", "exec")

    def test_unit_path_injection_and_foreign_configuration_are_rejected(self):
        for index, value in [
            (1, "/other"),
            (2, "/mnt/usb1%h"),
            (3, "invalid\nvalue"),
            (4, "a.service\nExecStart=x"),
            (5, "/tmp/foreign"),
        ]:
            args = self.args()
            args[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                package_supervisor.build(*args)

    def test_generated_command_actually_executes_the_embedded_loader(self):
        with mock.patch.object(
            package_supervisor, "BOOTSTRAP", "print('verified-loader-executed')"
        ):
            _, unit, _ = package_supervisor.build(*self.args())
        command = next(
            line.removeprefix("ExecStart=")
            for line in unit.splitlines()
            if line.startswith("ExecStart=")
        )
        argv = shlex.split(command)
        result = subprocess.run(
            [sys.executable, *argv[1:]], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "verified-loader-executed")
