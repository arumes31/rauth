"""Opt-in real-host descriptor/bootstrap checks; creates no Docker objects."""

import hashlib
import shlex
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import package_supervisor
import supervise


@unittest.skipUnless(
    sys.platform == "linux" and os.environ.get("RAUTH_GUARD_EXPECTED_STORAGE"),
    "requires explicit verified Linux test root",
)
class LinuxTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads(
            Path(os.environ["RAUTH_GUARD_EXPECTED_STORAGE"]).read_text()
        )
        self.expected = {
            k: self.expected[k]
            for k in (
                "node",
                "mode",
                "mount",
                "uuid",
                "root",
                "usb",
                "minimum_free_bytes",
                "minimum_available_memory",
            )
        }
        with supervise.Storage(self.expected, capacity=True):
            self.scratch = Path(
                tempfile.mkdtemp(prefix="guard-native-", dir=self.expected["root"])
            )

    def tearDown(self):
        # Only the exact freshly created scratch tree; never follow a symlink.
        self.assertEqual(self.scratch.parent, Path(self.expected["root"]))
        self.assertTrue(self.scratch.name.startswith("guard-native-"))
        self.assertFalse(self.scratch.is_symlink())
        shutil.rmtree(self.scratch)

    def test_held_sources_reject_symlink_fifo_foreign_mount_and_private_mode(self):
        private = self.scratch / "private"
        private.write_bytes(b"retained-private-bytes")
        private.chmod(0o600)
        symlink = self.scratch / "alias"
        symlink.symlink_to(private)
        fifo = self.scratch / "fifo"
        os.mkfifo(fifo, 0o600)
        parent = self.scratch / "parent"
        parent.symlink_to(self.scratch, target_is_directory=True)
        with supervise.Storage(self.expected) as storage:
            self.assertEqual(storage.private(private), b"retained-private-bytes")
            for path in (symlink, fifo, parent / private.name, Path("/run")):
                with (
                    self.subTest(path=str(path)),
                    self.assertRaises((supervise.Fault, ValueError, OSError)),
                ):
                    with storage.source(path):
                        self.fail("unsafe source accepted")
            private.chmod(0o644)
            with self.assertRaises(supervise.Fault):
                storage.private(private)

    def test_atomic_file_keeps_mode_owner_and_old_descriptor(self):
        directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY)
        try:
            supervise.atomic(directory, "file", b"before", 0o600)
            old = os.open("file", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                supervise.atomic(directory, "file", b"after", 0o600)
                self.assertEqual(os.read(old, 20), b"before")
                self.assertEqual((self.scratch / "file").read_bytes(), b"after")
                info = (self.scratch / "file").stat()
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid), (0o600, 0))
            finally:
                os.close(old)
        finally:
            os.close(directory)

    def test_last_mount_observation_cannot_change_identity(self):
        row = supervise.observation(self.expected["mount"])
        foreign = dict(row, uuid="foreign-filesystem")
        with mock.patch("supervise.observation", side_effect=[row, row, foreign]):
            with self.assertRaises(supervise.StorageFault):
                with supervise.Storage(self.expected):
                    self.fail("late foreign mount accepted")

    def test_pinned_memory_bootstrap_accepts_only_verified_bundle_before_child(self):
        marker = self.scratch / "child-marker"
        modules = {
            "render": "",
            "prepare": "",
            "supervise": "def main():\n    open("
            + repr(str(marker))
            + ", 'w').write('executed')\n",
        }
        body = json.dumps({"schema": 1, "modules": modules}).encode()
        bundle = self.scratch / "bundle.json"
        bundle.write_bytes(body)
        bundle.chmod(0o600)
        digest = hashlib.sha256(body).hexdigest()

        _, unit, _ = package_supervisor.build(
            Path(package_supervisor.__file__).parent,
            self.expected["root"],
            self.expected["mount"],
            self.expected["uuid"],
            "native-bootstrap",
            self.expected["root"] + "/supervision/config.json",
        )
        command = shlex.split(
            next(
                line.removeprefix("ExecStart=")
                for line in unit.splitlines()
                if line.startswith("ExecStart=")
            )
        )[4]

        def run(path=bundle, pin=digest, uuid=None):
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    command,
                    str(path),
                    pin,
                    self.expected["mount"],
                    uuid or self.expected["uuid"],
                    str(self.scratch / "config.json"),
                ],
                capture_output=True,
                timeout=10,
            )

        self.assertEqual(run().returncode, 0)
        self.assertEqual(marker.read_text(), "executed")
        marker.unlink()
        alias = self.scratch / "alias"
        alias.symlink_to(bundle)
        fifo = self.scratch / "fifo"
        os.mkfifo(fifo)
        for path, pin, uuid in [
            (bundle, "0" * 64, None),
            (bundle, digest, "wrong-filesystem"),
            (alias, digest, None),
            (fifo, digest, None),
        ]:
            with self.subTest(path=str(path), uuid=uuid):
                self.assertNotEqual(run(path, pin, uuid).returncode, 0)
                self.assertFalse(marker.exists())
        bundle.chmod(0o644)
        self.assertNotEqual(run().returncode, 0)
        self.assertFalse(marker.exists())
        bundle.chmod(0o600)
        os.chown(bundle, 10001, 10001)
        self.assertNotEqual(run().returncode, 0)
        self.assertFalse(marker.exists())
        os.chown(bundle, 0, 0)
        modules["supervise"] = (
            "class Fault(RuntimeError): pass\n"
            "def main():\n    raise ValueError('private-db-url=postgres://hidden-secret')\n"
        )
        body = json.dumps({"schema": 1, "modules": modules}).encode()
        bundle.write_bytes(body)
        bundle.chmod(0o600)
        failure = run(bundle, hashlib.sha256(body).hexdigest())
        self.assertNotEqual(failure.returncode, 0)
        self.assertNotIn(b"hidden-secret", failure.stderr)
        report = json.loads(failure.stderr)
        self.assertEqual(report["phase"], "supervision")
        self.assertEqual(report["exception"], "ValueError")
        self.assertTrue(any(frame["function"] == "main" for frame in report["frames"]))
        modules["supervise"] = modules["supervise"].replace(
            "ValueError('private-db-url=postgres://hidden-secret')",
            "Fault('expected_writable_uuid_absent')",
        )
        body = json.dumps({"schema": 1, "modules": modules}).encode()
        bundle.write_bytes(body)
        bundle.chmod(0o600)
        failure = run(bundle, hashlib.sha256(body).hexdigest())
        self.assertNotEqual(failure.returncode, 0)
        report = json.loads(failure.stderr)
        self.assertEqual(report["phase"], "supervision")
        self.assertEqual(report["exception"], "Fault")
        self.assertEqual(report["reason"], "expected_writable_uuid_absent")

    def test_explicit_read_execute_modes_survive_service_umask(self):
        directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY)
        previous = os.umask(0o077)
        try:
            for mode in (0o444, 0o555, 0o600):
                name = "mode-" + str(mode)
                supervise.atomic(directory, name, b"fixture", mode)
                self.assertEqual(
                    stat.S_IMODE((self.scratch / name).stat().st_mode), mode
                )
        finally:
            os.umask(previous)
            os.close(directory)

    @unittest.skipUnless(
        os.environ.get("RAUTH_GUARD_EXEC") and os.environ.get("RAUTH_GUARD_IMAGE"),
        "requires explicit native launcher and preloaded image",
    )
    def test_real_supervisor_witness_executes_nonroot_child_and_rejects_foreign_fsid(
        self,
    ):
        import hashlib

        executable = Path(os.environ["RAUTH_GUARD_EXEC"])
        cfg = {
            "storage": dict(self.expected, node="native-guard-" + str(os.getpid())),
            "launcher_file": str(executable),
            "launcher_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        }
        data = self.scratch / "data"
        data.mkdir(mode=0o700)
        os.chown(data, 10001, 10001)
        ram = supervise.RAM(cfg)
        previous = os.umask(0o077)
        names = []
        created_directory = False
        try:
            ram.path.mkdir(mode=0o700, parents=True)
            created_directory = True
            subprocess.run(
                [
                    "mount",
                    "-t",
                    "tmpfs",
                    "-o",
                    "rw,exec,nosuid,nodev,mode=0700,size=8m",
                    "tmpfs",
                    str(ram.path),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
            ram.open()
            with supervise.Storage(self.expected, capacity=True) as storage:
                ram.launcher(storage, cfg)
                ram.attest(
                    storage,
                    {"role": "app"},
                    [{"Source": str(data), "Destination": "/app/data", "RW": True}],
                )
            self.assertEqual(stat.S_IMODE((ram.path / "exec").stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((ram.path / "app.json").stat().st_mode), 0o444
            )
            image = os.environ["RAUTH_GUARD_IMAGE"]
            metadata = json.loads(
                subprocess.check_output(["docker", "image", "inspect", image])
            )[0]

            def run(child=None):
                name = "rauth-guard-native-" + str(os.getpid()) + "-" + str(len(names))
                names.append(name)
                command = [
                    "docker",
                    "run",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--user",
                    "10001:10001",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "64m",
                    "--memory-swap",
                    "64m",
                    "--pids-limit",
                    "32",
                ]
                for source, target, readonly in [
                    (data, "/app/data", False),
                    (ram.path / "exec", "/guard/exec", True),
                    (ram.path / "app.json", "/guard/identity.json", True),
                ]:
                    command += [
                        "--mount",
                        "type=bind,src="
                        + str(source)
                        + ",dst="
                        + target
                        + (",readonly" if readonly else ""),
                    ]
                for destination in metadata["Config"].get("Volumes") or {}:
                    command += ["--tmpfs", destination + ":rw,nosuid,nodev,size=1m"]
                command += [
                    "--entrypoint",
                    "/guard/exec",
                    image,
                    "--uuid",
                    self.expected["uuid"],
                    "--role",
                    "app",
                    "--",
                    *(
                        child
                        if child is not None
                        else ["/bin/sh", "-c", "echo executed > /app/data/child"]
                    ),
                ]
                return subprocess.run(command, capture_output=True, timeout=25)

            result = run()
            self.assertEqual(
                result.returncode, 0, result.stderr.decode(errors="replace")
            )
            self.assertEqual((data / "child").read_text().strip(), "executed")
            (data / "child").unlink()
            missing = run(["/missing/verified-child"])
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(b"verified child process could not start", missing.stderr)
            self.assertFalse((data / "child").exists())
            witness = json.loads((ram.path / "app.json").read_text())
            witness["targets"][0]["fsid"] = str(int(witness["targets"][0]["fsid"]) ^ 1)
            supervise.atomic(ram.fd, "app.json", json.dumps(witness).encode())
            self.assertNotEqual(run().returncode, 0)
            self.assertFalse((data / "child").exists())
        finally:
            os.umask(previous)
            cleanup_errors = []
            for name in names:
                try:
                    result = subprocess.run(
                        ["docker", "rm", "-f", name], capture_output=True, timeout=15
                    )
                    if result.returncode:
                        cleanup_errors.append("container removal failed: " + name)
                except (OSError, subprocess.SubprocessError):
                    cleanup_errors.append("container removal unavailable: " + name)
            # Attempt every release even if one exited container cannot be removed.
            try:
                for name in ("app.json", "exec") if ram.fd is not None else ():
                    try:
                        os.unlink(name, dir_fd=ram.fd)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        cleanup_errors.append("transient metadata removal failed")
            finally:
                ram.close()
                if created_directory:
                    try:
                        mounted = subprocess.run(
                            [
                                "findmnt",
                                "-rn",
                                "--mountpoint",
                                str(ram.path),
                                "-o",
                                "FSTYPE",
                            ],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if mounted.returncode == 0:
                            if mounted.stdout.strip() != "tmpfs":
                                raise RuntimeError("Unexpected native test mount")
                            result = subprocess.run(
                                ["umount", str(ram.path)],
                                capture_output=True,
                                timeout=10,
                            )
                            if result.returncode:
                                raise RuntimeError("Native test unmount failed")
                        elif mounted.returncode != 1:
                            raise RuntimeError("Native test mount observation failed")
                        os.rmdir(ram.path)
                    except (OSError, RuntimeError, subprocess.SubprocessError):
                        cleanup_errors.append("test RAM release unavailable")
            if cleanup_errors:
                self.fail("; ".join(cleanup_errors))
