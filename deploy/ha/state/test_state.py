import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import render
import prepare
import entrypoint

spec = importlib.util.spec_from_file_location("wal_archive", Path(__file__).with_name("archive.py"))
wal_archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wal_archive)


def fixture():
    return {"schema": 1, "mode": "isolated-test", "cluster": "rauth-test-fixture",
            "images": {k: "example.invalid/" + k + "@sha256:" + "a" * 64 for k in ("postgres", "etcd", "router")},
            "nodes": [{"name": name, "ip": f"100.64.99.{i + 1}", "state": i < 3,
                       "root": "/mnt/usb1/rauth/rauth-test-state" if i == 2 else "/opt/rauth/rauth-test-state",
                       "mount": "/mnt/usb1" if i == 2 else "/", "uuid": "12345678-abcd-1234-abcd-123456789012", "usb": i == 2}
                      for i, name in enumerate(("state-a", "state-b", "state-c", "worker-d"))]}


class ManifestTests(unittest.TestCase):
    def test_unsafe_manifests_rejected(self):
        edits = [("mode", "production"), ("schema", True), ("cluster", "production"), ("extra", 1)]
        for key, value in edits:
            with self.subTest(key=key):
                m = fixture(); m[key] = value
                with self.assertRaises(ValueError): render.validate(m)
        for field, value in (("name", "../escape"), ("root", "/"), ("root", "/opt/../rauth-test-state"),
                             ("root", "/opt//rauth-test-state"), ("root", "/opt/rauth-test-state\n"),
                             ("uuid", ""), ("ip", "0.0.0.0"), ("state", 1)):
            with self.subTest(field=field, value=value):
                m = fixture(); m["nodes"][0][field] = value
                with self.assertRaises(ValueError): render.validate(m)
        for mode in ("duplicate-ip", "duplicate-name", "two-state", "unpinned", "usb-fallback"):
            with self.subTest(mode=mode):
                m = fixture()
                if mode == "duplicate-ip": m["nodes"][1]["ip"] = m["nodes"][0]["ip"]
                if mode == "duplicate-name": m["nodes"][1]["name"] = m["nodes"][0]["name"]
                if mode == "two-state": m["nodes"][0]["state"] = False
                if mode == "unpinned": m["images"]["etcd"] = "etcd:latest"
                if mode == "usb-fallback": m["nodes"][2]["root"] = "/opt/rauth-test-state"
                with self.assertRaises(ValueError): render.validate(m)

    def test_every_node_has_only_guarded_binds_and_own_service_namespace(self):
        m = fixture()
        for n in m["nodes"]:
            files = render.render(m, n["name"])
            services = json.loads(files["compose.state.json"])["services"]
            self.assertEqual(set(services), {"etcd", "patroni", "sql-router"} if n["state"] else {"sql-router"})
            for service in services.values():
                self.assertEqual(service["network_mode"], "service:tailscale")
                self.assertTrue(service["read_only"])
                self.assertNotIn("ports", service)
                self.assertNotIn("privileged", service)
                self.assertNotIn("devices", service)
                for mount in service["volumes"]:
                    self.assertEqual(mount["type"], "bind")
                    self.assertFalse(mount["bind"]["create_host_path"])
                    self.assertTrue(mount["source"].startswith(n["root"] + "/"))
            if n["state"]:
                targets = [v["target"] for v in services["patroni"]["volumes"]]
                self.assertIn("/var/lib/postgresql", targets, "Cover PG18 image VOLUME, preventing anonymous data")
                self.assertIn("/var/lib/rauth-wal", targets)
                pg = json.loads(files["config/patroni.json"])
                dcs = pg["bootstrap"]["dcs"]
                self.assertTrue(dcs["synchronous_mode"] and dcs["synchronous_mode_strict"])
                self.assertEqual(dcs["synchronous_node_count"], 1)
                self.assertFalse(dcs["failsafe_mode"])
                self.assertEqual(pg["watchdog"]["mode"], "off", "Explicit test-only fixture; no host reset")
                params = dcs["postgresql"]["parameters"]
                self.assertEqual(params["synchronous_commit"], "on")
                self.assertEqual(params["fsync"], "on")
                self.assertEqual(pg["restapi"]["verify_client"], "required")
                self.assertNotIn('"password":', files["config/patroni.json"])

    def test_router_uses_locked_primary_health_and_tls_without_sql_termination(self):
        files = render.render(fixture(), "worker-d")
        cfg = files["config/haproxy.cfg"]
        self.assertIn("bind 100.64.99.4:6543", cfg)
        self.assertIn("GET /primary", cfg)
        self.assertEqual(cfg.count("verify required"), 3)
        self.assertEqual(cfg.count("check-ssl"), 3)
        self.assertEqual(cfg.count("shutdown-sessions"), 3)
        self.assertNotIn(" ssl ", cfg, "Only health traffic is HAProxy TLS, SQL passes through")

    def test_missing_usb_never_prepares_directories(self):
        expected = json.loads(render.render(fixture(), "state-c")["expected-storage.json"])
        for row in ({"target": "/", "uuid": expected["uuid"], "fstype": "ext4", "options": "rw"},
                    {"target": "/mnt/usb1", "uuid": "different", "fstype": "ext4", "options": "rw"},
                    {"target": "/mnt/usb1", "uuid": expected["uuid"], "fstype": "ext4", "options": "ro"}):
            with self.subTest(row=row):
                with self.assertRaises(ValueError): prepare.verify_mount(expected, {"filesystems": [row]})
        prepare.verify_mount(expected, {"filesystems": [{"target": "/mnt/usb1", "uuid": expected["uuid"], "fstype": "ext4", "options": "rw,relatime"}]})
        bad = copy.deepcopy(expected); bad["directories"]["../escape"] = 999
        with self.assertRaises(ValueError): prepare.validate_expectation(bad)

    def test_private_secrets_are_merged_only_at_runtime(self):
        config = json.loads(render.render(fixture(), "state-a")["config/patroni.json"])
        secrets = {name: "synthetic-" + name + "-" + "x" * 32 for name in ("superuser", "replication", "rewind", "rest")}
        result = entrypoint.merge(config, secrets)
        self.assertEqual(result["postgresql"]["authentication"]["replication"]["password"], secrets["replication"])
        self.assertEqual(result["ctl"]["authentication"]["password"], secrets["rest"])
        for value in ("short", "x" * 31 + "\n", 123):
            bad = dict(secrets, rest=value)
            with self.assertRaises(ValueError): entrypoint.merge(config, bad)


@unittest.skipUnless(sys.platform == "linux", "Native Linux filesystem guarantees")
class NativeFilesystemTests(unittest.TestCase):
    def test_archive_is_synced_idempotent_and_refuses_conflicts(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); source = root / "wal"; source.write_bytes(b"WAL-A" * 4096)
            archive = root / "archive"; archive.mkdir()
            name = "000000010000000000000001"
            wal_archive.archive(source, name, archive)
            self.assertEqual((archive / name).read_bytes(), source.read_bytes())
            wal_archive.archive(source, name, archive)
            source.write_bytes(b"conflicting")
            with self.assertRaises(ValueError): wal_archive.archive(source, name, archive)
            self.assertNotEqual((archive / name).read_bytes(), source.read_bytes())
            self.assertFalse(list(archive.glob(".pending-*")))
            with self.assertRaises(ValueError): wal_archive.archive(source, "../escape", archive)

    def test_archive_rejects_symlink_and_budget_exhaustion(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); source = root / "wal"; source.write_bytes(b"x" * 128)
            archive = root / "archive"; archive.mkdir()
            link = root / "link"; link.symlink_to(source)
            name = "000000010000000000000001"
            with self.assertRaises(OSError): wal_archive.archive(link, name, archive)
            old = wal_archive.LIMIT
            try:
                wal_archive.LIMIT = 64
                with self.assertRaises(ValueError): wal_archive.archive(source, name, archive)
                self.assertFalse(list(archive.iterdir()))
            finally: wal_archive.LIMIT = old

    def test_directory_fd_blocks_symlink_redirection(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); target = root / "target"; target.mkdir(mode=0o700)
            link = root / "link"; link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError): prepare.open_directory(link)
            anchor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError): prepare.ensure_tree(anchor, "link/escape", os.getuid(), os.fstat(anchor).st_dev)
                self.assertFalse((target / "escape").exists())
            finally: os.close(anchor)

    def test_same_device_bind_mount_cannot_escape_guarded_root(self):
        if not shutil.which("unshare") or not shutil.which("mount"):
            self.skipTest("Isolated mount namespace tools unavailable")
        code = """
import os,tempfile
from pathlib import Path
import prepare
with tempfile.TemporaryDirectory() as t:
 root=Path(t);source=root/'outside';source.mkdir(mode=0o700)
 target=root/'nested';target.mkdir(mode=0o700)
 import subprocess
 subprocess.run(['mount','--bind',str(source),str(target)],check=True)
 anchor=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 child=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
 try:
  assert os.fstat(anchor).st_dev == os.fstat(child).st_dev
  assert prepare.mount_identity(anchor) != prepare.mount_identity(child)
  try:prepare.ensure_tree(anchor,'nested/escape',os.getuid(),os.fstat(anchor).st_dev)
  except ValueError:pass
  else:raise AssertionError('Same-device bind mount was accepted')
  assert not (source/'escape').exists()
 finally:
  os.close(child);os.close(anchor)
  subprocess.run(['umount',str(target)],check=True)
"""
        result = subprocess.run(["unshare", "--mount", "--propagation", "private", sys.executable, "-c", code],
                                cwd=Path(__file__).parent, capture_output=True, text=True)
        if result.returncode and result.stderr.startswith("unshare:") and "Operation not permitted" in result.stderr:
            self.skipTest("Private mount namespace requires host privilege")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
