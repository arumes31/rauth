import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import observe


def config():
    return {
        "schema": 1,
        "cluster_id": "11111111-1111-4111-8111-111111111111",
        "mode": "isolated-test",
        "source_ip": "100.64.99.1",
        "expected_system_id": "12345",
        "expected_dcs_cluster_id": "67890",
        "output_dir": "/output",
        "output_device": "8:1",
        "members": [
            {"name": name, "ip": "100.64.99." + str(i + 1)}
            for i, name in enumerate(["state-a", "state-b", "state-c"])
        ],
        **{
            name: "/pki/" + name
            for name in [
                "patroni_ca",
                "patroni_certificate",
                "patroni_key",
                "etcd_ca",
                "etcd_certificate",
                "etcd_key",
            ]
        },
    }


class ObservationTests(unittest.TestCase):
    def test_only_exact_private_service_topology_and_separate_keys_are_accepted(self):
        self.assertEqual(observe.validate(config()), config())
        for change in [
            lambda c: c.update(source_ip="203.0.113.1"),
            lambda c: c["members"][0].update(ip="127.0.0.1"),
            lambda c: c["members"][1].update(ip=c["members"][0]["ip"]),
            lambda c: c.update(etcd_key="/output/private.key"),
            lambda c: c.update(expected_dcs_cluster_id="0"),
            lambda c: c.update(extra="unknown"),
            lambda c: c.update(output_device="08:1"),
        ]:
            c = config()
            change(c)
            with self.subTest(c=c), self.assertRaises((ValueError, TypeError)):
                observe.validate(c)
        with self.assertRaises(ValueError):
            observe.request(config(), config()["members"][0], "etcd", "/v3/kv/put")

    def test_probe_verifies_expected_cluster_and_primary_lease_without_copying_upstream_text(
        self,
    ):
        c = config()
        expires = time.time() + 86400

        def response(_config, _member, service, path):
            if path in ("/patroni", "/primary"):
                return (
                    200,
                    {
                        "state": "running",
                        "role": "primary",
                        "timeline": 3,
                        "server_version": 180006,
                        "database_system_identifier": "12345",
                        "replication": [{"state": "streaming", "sync_state": "sync"}],
                        "xlog": {"location": 100},
                        "untrusted": "<script>",
                    },
                    expires,
                )
            if path == "/health":
                return 200, {"health": "true"}, expires
            return (
                200,
                {
                    "header": {"cluster_id": "67890", "member_id": "11"},
                    "leader": "11",
                    "dbSize": "1024",
                    "dbSizeQuota": "67108864",
                },
                expires,
            )

        with patch.object(observe, "request", side_effect=response):
            r = observe.member_probe(c, c["members"][0])
        self.assertTrue(r["database_ready"])
        self.assertTrue(r["leader_verified"])
        self.assertTrue(r["dcs_ready"])
        self.assertEqual(r["sync_replicas"], 1)
        self.assertNotIn("script", json.dumps(r))

        def no_lease(config, member, service, path):
            code, data, expiry = response(config, member, service, path)
            return (503, data, expiry) if path == "/primary" else (code, data, expiry)

        with patch.object(observe, "request", side_effect=no_lease):
            r = observe.member_probe(c, c["members"][0])
        self.assertFalse(
            r["leader_verified"], "a role string alone does not prove a live lease"
        )

        def foreign(config, member, service, path):
            code, data, expiry = response(config, member, service, path)
            if path == "/v3/maintenance/status":
                data["header"]["cluster_id"] = "99999"
            return code, data, expiry

        with patch.object(observe, "request", side_effect=foreign):
            r = observe.member_probe(c, c["members"][0])
        self.assertEqual(r["issue"], "identity_mismatch")
        self.assertEqual(r["dcs_cluster_id"], "99999")

    def test_unreachable_peer_never_emits_exception_or_credentials(self):
        with patch.object(
            observe, "request", side_effect=RuntimeError("private-key-path and secret")
        ):
            r = observe.member_probe(config(), config()["members"][0])
        self.assertFalse(r["database_ready"])
        self.assertFalse(r["dcs_ready"])
        self.assertNotIn("secret", json.dumps(r))
        self.assertNotIn("private", json.dumps(r))

    def test_parent_deadline_kills_a_real_stalled_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "slow.py"
            script.write_text("import time\ntime.sleep(60)\n")
            start = time.monotonic()
            with patch.object(observe, "__file__", str(script)):
                result = observe.bounded_probe(config(), config()["members"][0])
            self.assertLess(time.monotonic() - start, 8)
            self.assertFalse(result["database_ready"])
            self.assertEqual(result["issue"], "unavailable")

    def test_capture_reports_lag_only_on_the_same_verified_timeline(self):
        rows = []
        for i, member in enumerate(config()["members"]):
            row = observe.unavailable(member["name"])
            row.update(
                database_ready=True,
                role="primary" if i == 0 else "replica",
                leader_verified=i == 0,
                system_id="12345",
                timeline=3 if i < 2 else 2,
                _position=100 - i * 10,
                issue="",
            )
            rows.append(row)
        with patch.object(
            observe,
            "bounded_probe",
            side_effect=lambda c, m: copy.deepcopy(
                rows[[x["name"] for x in c["members"]].index(m["name"])]
            ),
        ):
            report = json.loads(observe.capture(config()))
        self.assertEqual(report["members"][1]["lag_bytes"], 10)
        self.assertNotIn("lag_bytes", report["members"][2])
        self.assertTrue(all("_position" not in row for row in report["members"]))


@unittest.skipUnless(
    sys.platform == "linux", "Native directory-fd and filesystem guarantees"
)
class OutputTests(unittest.TestCase):
    def test_wrong_device_and_symlink_output_fail_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            c = config()
            c["output_dir"] = directory
            c["output_device"] = "999:999"
            with self.assertRaises(ValueError):
                observe.output_directory(c)
            self.assertEqual(list(Path(directory).iterdir()), [])
            device = os.stat(directory).st_dev
            c["output_device"] = str(os.major(device)) + ":" + str(os.minor(device))
            fd = observe.output_directory(c)
            try:
                observe.publish(fd, b'{"complete":true}\n')
                self.assertEqual(
                    (Path(directory) / "ha.json").read_text(), '{"complete":true}\n'
                )
                self.assertEqual(
                    (Path(directory) / "ha.json").stat().st_mode & 0o777, 0o600
                )
                (Path(directory) / "ha.json").unlink()
                outside = Path(directory) / "outside"
                outside.write_text("original")
                (Path(directory) / "ha.json").symlink_to(outside)
                with self.assertRaises(ValueError):
                    observe.publish(fd, b"{}")
                self.assertEqual(outside.read_text(), "original")
            finally:
                os.close(fd)
