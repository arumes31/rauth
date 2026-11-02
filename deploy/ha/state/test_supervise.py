import contextlib
import copy
import io
from pathlib import PurePosixPath
import unittest
from unittest import mock
import subprocess

import supervise


def bindings(kind):
    targets = {
        "tailscale": ["/var/lib/tailscale"],
        "patroni": [
            "/var/lib/postgresql",
            "/var/lib/rauth-wal",
            "/var/lib/rauth-archive",
        ],
        "app": ["/app/data"],
    }[kind]
    return [
        {
            "source": "/opt/rauth/rauth-test-state/data-" + kind + str(i),
            "target": target,
            "writable": True,
        }
        for i, target in enumerate(targets)
    ]


def config():
    roles = []
    for kind, name in (
        ("tailscale", "rauth-tailscale"),
        ("patroni", "rauth-test-patroni"),
        ("app", "rauth-test-app"),
    ):
        labels = {"org.rauth.fixture": "guard-test"}
        if kind == "app":
            labels["org.rauth.state-authority"] = "isolated-ha-test"
        roles.append(
            {
                "role": kind,
                "name": name,
                "image": "sha256:" + "a" * 64,
                "labels": labels,
                "binds": bindings(kind),
                "remap": [],
            }
        )
    return {
        "schema": 2,
        "storage": {
            "node": "state-a",
            "mode": "isolated-test",
            "mount": "/",
            "uuid": "11111111-1111-4111-8111-111111111111",
            "root": "/opt/rauth/rauth-test-state",
            "usb": False,
            "minimum_free_bytes": 20 * 1024**3,
            "minimum_available_memory": 650 * 1024**2,
        },
        "service_ip": "100.64.99.1",
        "launcher_file": "/opt/rauth/rauth-test-state/programs/guard",
        "launcher_sha256": "b" * 64,
        "roles": roles,
    }


class RAM:
    def __init__(self, cfg):
        self.uuid = cfg["storage"]["uuid"]
        self.path = PurePosixPath("/run/rauth-ha/state-a")
        self.calls = []
        self.closed = False

    def launcher(self, *_):
        self.calls.append("launcher")

    def attest(self, _storage, role, _mounts):
        self.calls.append("attest-" + role["role"])

    def close(self):
        self.closed = True


class Storage:
    def __init__(self):
        self.failure = None
        self.capacity_failure = False
        self.calls = []

    @contextlib.contextmanager
    def __call__(self, _expected, capacity=False):
        self.calls.append(capacity)
        if self.failure:
            raise self.failure
        if capacity and self.capacity_failure:
            raise supervise.Fault("startup_capacity_unavailable")
        yield self


class Docker:
    def __init__(self, cfg, ram):
        self.rows, self.calls = {}, []
        self.fail_start = False
        self.ready = True
        self.network_equal = True
        for index, role in enumerate(cfg["roles"]):
            kind = role["role"]
            mounts = [
                {
                    "Type": "bind",
                    "Source": pin["source"],
                    "Destination": pin["target"],
                    "RW": pin["writable"],
                }
                for pin in role["binds"]
            ]
            mounts += [
                {
                    "Type": "bind",
                    "Source": str(ram.path / "exec"),
                    "Destination": "/guard/exec",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": str(ram.path / (kind + ".json")),
                    "Destination": "/guard/identity.json",
                    "RW": False,
                },
            ]
            self.rows[role["name"]] = {
                "Id": "container-" + kind,
                "Name": "/" + role["name"],
                "Image": role["image"],
                "State": {"Running": True, "Pid": index + 10},
                "HostConfig": {
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "RestartPolicy": {"Name": "no"},
                    "NetworkMode": "bridge"
                    if kind == "tailscale"
                    else "container:container-tailscale",
                },
                "Config": {
                    "Labels": copy.deepcopy(role["labels"]),
                    "Entrypoint": [
                        "/guard/exec",
                        "--uuid",
                        ram.uuid,
                        "--role",
                        kind,
                        "--",
                        "/original",
                    ],
                    "Env": [
                        "AUTH_STATE_MODE=postgres",
                        "CLUSTER_CONFIG_FILE=/app/data/config/node.json",
                    ],
                },
                "Mounts": mounts,
            }

    def inspect(self, name):
        self.calls.append(("inspect", name))
        return copy.deepcopy(self.rows[name])

    def by_id(self, ident):
        return next(row for row in self.rows.values() if row["Id"] == ident)

    def start(self, ident):
        self.calls.append(("start", ident))
        self.by_id(ident)["State"]["Running"] = not self.fail_start

    def stop(self, ident):
        self.calls.append(("stop", ident))
        self.by_id(ident)["State"]["Running"] = False

    def provider_ready(self, ident, _address):
        return self.ready and self.by_id(ident)["State"]["Running"]

    def same_network(self, *_):
        return self.network_equal


def fixture():
    cfg = config()
    ram, storage = RAM(cfg), Storage()
    docker = Docker(cfg, ram)
    clock = [0]
    actor = supervise.Supervisor(
        cfg, docker=docker, storage=storage, ram=ram, now=lambda: clock[0]
    )
    return cfg, ram, storage, docker, clock, actor


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    def tearDown(self):
        self.output.__exit__(None, None, None)

    def test_scope_and_duplicate_configuration(self):
        self.assertEqual(supervise.validate(config()), config())
        edits = [
            lambda c: c["storage"].update(root="/"),
            lambda c: c["storage"].update(usb=True),
            lambda c: c.update(service_ip="192.0.2.1"),
            lambda c: c.update(launcher_file="/tmp/unpinned"),
            lambda c: c["roles"][2]["labels"].clear(),
            lambda c: c["roles"][2]["labels"].update(
                {"org.rauth.state-authority": "legacy"}
            ),
            lambda c: c["roles"].append(copy.deepcopy(c["roles"][0])),
        ]
        for edit in edits:
            c = config()
            edit(c)
            with self.subTest(c=c), self.assertRaises(supervise.Fault):
                supervise.validate(c)
        with self.assertRaises(supervise.Fault):
            supervise.document(b'{"schema":1,"SCHEMA":1}')

    def test_wrong_storage_never_inspects_or_starts_a_container(self):
        _, ram, storage, docker, _, actor = fixture()
        storage.failure = supervise.StorageFault("wrong_uuid")
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        self.assertEqual(docker.calls, [])
        self.assertTrue(ram.closed)

    def test_provider_failure_stops_clients_before_restarting_provider(self):
        _, ram, _, docker, _, actor = fixture()
        docker.rows["rauth-tailscale"]["State"]["Running"] = False
        actor.tick()
        actions = [call for call in docker.calls if call[0] != "inspect"]
        self.assertEqual(
            actions[:3],
            [
                ("stop", "container-patroni"),
                ("stop", "container-app"),
                ("start", "container-tailscale"),
            ],
        )
        self.assertTrue(all(row["State"]["Running"] for row in docker.rows.values()))
        self.assertEqual(ram.calls.count("launcher"), 3)

    def test_local_role_failure_restarts_only_that_role(self):
        _, ram, _, docker, _, actor = fixture()
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        actor.tick()
        self.assertEqual(
            [c for c in docker.calls if c[0] in ("start", "stop")],
            [("start", "container-app")],
        )
        self.assertEqual(ram.calls, ["launcher", "attest-app"])

    def test_capacity_or_dependency_error_keeps_healthy_roles_and_does_not_spend_restart_budget(
        self,
    ):
        _, _, storage, docker, _, actor = fixture()
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        storage.capacity_failure = True
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        self.assertFalse(any(c[0] in ("start", "stop") for c in docker.calls))
        self.assertEqual(len(actor.attempts["app"]), 0)
        self.assertTrue(docker.rows["rauth-test-patroni"]["State"]["Running"])

    def test_actual_restart_attempts_are_bounded(self):
        _, _, _, docker, clock, actor = fixture()
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        docker.fail_start = True
        for _ in range(4):
            actor.tick()
        self.assertEqual(sum(c[0] == "start" for c in docker.calls), 3)
        clock[0] = 301
        actor.tick()
        self.assertEqual(sum(c[0] == "start" for c in docker.calls), 4)

    def test_namespace_drift_stops_client_before_reattaching(self):
        _, _, _, docker, _, actor = fixture()
        docker.network_equal = False
        actor.tick()
        actions = [c for c in docker.calls if c[0] != "inspect"]
        self.assertIn(("stop", "container-patroni"), actions)
        self.assertLess(
            actions.index(("stop", "container-patroni")),
            actions.index(("start", "container-patroni")),
        )

    def test_automatic_restart_privilege_unwrapped_and_volume_metadata_are_rejected(
        self,
    ):
        cfg, ram, _, docker, _, _ = fixture()
        role = cfg["roles"][2]
        for edit in [
            lambda r: r["HostConfig"]["RestartPolicy"].update(Name="always"),
            lambda r: r["HostConfig"].update(Privileged=True),
            lambda r: r["Config"].update(Entrypoint=["/original"]),
            lambda r: r["Config"].update(Labels=None),
            lambda r: r["Mounts"][0].update(Type="volume"),
            lambda r: r["Mounts"][-1].update(RW=True),
            lambda r: r["Config"].update(Env=["AUTH_STATE_MODE=redis"]),
        ]:
            info = copy.deepcopy(docker.rows[role["name"]])
            edit(info)
            with self.assertRaises(supervise.Fault):
                supervise.container(role, info, ram, docker.rows["rauth-tailscale"])

    def test_missing_or_foreign_uuid_is_a_storage_fault(self):
        expected = config()["storage"]
        with self.assertRaises(supervise.StorageFault):
            supervise.check_mount(
                expected,
                {"target": "/", "uuid": "foreign", "fstype": "ext4", "options": "rw"},
            )

    def test_missing_mount_is_storage_fault_but_timeout_is_dependency_fault(self):
        with mock.patch(
            "supervise.subprocess.check_output",
            side_effect=subprocess.CalledProcessError(1, "findmnt"),
        ):
            with self.assertRaises(supervise.StorageFault):
                supervise.observation("/mnt/usb1")
        with mock.patch(
            "supervise.subprocess.check_output",
            side_effect=subprocess.TimeoutExpired("findmnt", 5),
        ):
            with self.assertRaises(supervise.Fault) as failure:
                supervise.observation("/mnt/usb1")
            self.assertNotIsInstance(failure.exception, supervise.StorageFault)

    def test_stop_failure_does_not_prevent_stopping_remaining_owned_roles(self):
        _, _, _, docker, _, actor = fixture()
        actor.inspect()
        original = docker.stop

        def stop(ident):
            if ident == "container-patroni":
                raise supervise.Fault("docker_unavailable")
            original(ident)

        docker.stop = stop
        actor.stop()
        self.assertIn(("stop", "container-app"), docker.calls)
        self.assertIn(("stop", "container-tailscale"), docker.calls)

    def test_verified_storage_loss_stops_owned_cohort_without_starting(self):
        _, _, storage, docker, _, actor = fixture()
        actor.tick()
        docker.calls.clear()
        storage.failure = supervise.StorageFault("uuid_changed")
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        actions = [c for c in docker.calls if c[0] in ("start", "stop")]
        self.assertEqual(
            actions,
            [
                ("stop", "container-patroni"),
                ("stop", "container-app"),
                ("stop", "container-tailscale"),
            ],
        )

    def test_unpinned_source_changes_and_sibling_prefixes_cannot_start(self):
        for source in ("/etc", "/opt/rauth/rauth-test-state/data-app0-sibling"):
            _, _, _, docker, _, actor = fixture()
            docker.rows["rauth-test-app"]["Mounts"][0]["Source"] = source
            docker.rows["rauth-test-app"]["State"]["Running"] = False
            with self.subTest(source=source), self.assertRaises(supervise.Fault):
                actor.run(once=True)
            self.assertFalse(any(call[0] == "start" for call in docker.calls))

    def test_explicit_bind_pins_allow_approved_sibling_data_roots(self):
        cfg = config()
        cfg["roles"][0]["binds"][0]["source"] = "/opt/rauth/tailscale"
        supervise.validate(cfg)
        ram, storage = RAM(cfg), Storage()
        docker = Docker(cfg, ram)
        docker.rows["rauth-tailscale"]["State"]["Running"] = False
        actor = supervise.Supervisor(cfg, docker=docker, storage=storage, ram=ram)
        actor.tick()
        self.assertIn(("start", "container-tailscale"), docker.calls)

    def test_unapproved_extra_and_writability_changes_are_rejected(self):
        cfg, ram, _, docker, _, _ = fixture()
        role = cfg["roles"][2]
        for edit in [
            lambda r: r["Mounts"].append(
                {"Type": "bind", "Source": "/etc", "Destination": "/extra", "RW": False}
            ),
            lambda r: r["Mounts"][0].update(RW=False),
        ]:
            row = copy.deepcopy(docker.rows[role["name"]])
            edit(row)
            with self.assertRaises(supervise.Fault):
                supervise.container(role, row, ram, docker.rows["rauth-tailscale"])
        for edit in [
            lambda c: c.update(schema=1),
            lambda c: c["roles"][0].update(binds=[]),
            lambda c: c["roles"][0]["binds"][0].update(writable=1),
            lambda c: c["roles"][0]["binds"][0].update(source="/"),
            lambda c: c["roles"][0]["binds"].append(
                copy.deepcopy(c["roles"][0]["binds"][0])
            ),
        ]:
            changed = config()
            edit(changed)
            with self.assertRaises(supervise.Fault):
                supervise.validate(changed)

    def test_role_preflight_failure_does_not_block_later_role_recovery(self):
        _, _, _, docker, _, actor = fixture()
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        docker.rows["rauth-test-app"]["State"]["Running"] = False

        def checked(_storage, role, _mounts):
            if role["role"] == "patroni":
                raise supervise.Fault("database_authority_changed")

        with mock.patch("supervise.remap", side_effect=checked):
            with self.assertRaises(supervise.Fault):
                actor.run(once=True)
        self.assertIn(("start", "container-app"), docker.calls)
        self.assertNotIn(("start", "container-patroni"), docker.calls)

    def test_foreign_role_metadata_cannot_block_valid_later_role(self):
        _, _, _, docker, _, actor = fixture()
        docker.rows["rauth-test-patroni"]["Config"]["Labels"] = None
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        self.assertIn(("start", "container-app"), docker.calls)
        self.assertNotIn(("start", "container-patroni"), docker.calls)

    def test_shared_launcher_failure_spends_no_role_budget(self):
        _, ram, _, docker, _, actor = fixture()
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        docker.rows["rauth-test-app"]["State"]["Running"] = False

        def unavailable(*_):
            raise supervise.Fault("launcher_hash_changed")

        ram.launcher = unavailable
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        self.assertFalse(any(c[0] == "start" for c in docker.calls))
        self.assertEqual(len(actor.attempts.get("patroni", ())), 0)
        self.assertEqual(len(actor.attempts.get("app", ())), 0)

    def test_role_preflight_failures_are_bounded_and_retry_after_window(self):
        _, _, _, docker, clock, actor = fixture()
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        calls = []

        def checked(_storage, role, _mounts):
            if role["role"] == "patroni":
                calls.append(role["role"])
                raise supervise.Fault("database_authority_changed")

        with mock.patch("supervise.remap", side_effect=checked):
            for _ in range(4):
                try:
                    actor.run(once=True)
                except supervise.Fault:
                    pass
            self.assertEqual(len(calls), 3)
            self.assertEqual(len(actor.attempts["patroni"]), 3)
            clock[0] = 301
            with self.assertRaises(supervise.Fault):
                actor.run(once=True)
            self.assertEqual(len(calls), 4)

    def test_role_attestation_failure_does_not_block_later_role(self):
        _, ram, _, docker, _, actor = fixture()
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        original = ram.attest

        def attest(storage, role, mounts):
            if role["role"] == "patroni":
                raise supervise.Fault("source_identity_changed")
            original(storage, role, mounts)

        ram.attest = attest
        with self.assertRaises(supervise.Fault):
            actor.run(once=True)
        self.assertIn(("start", "container-app"), docker.calls)
        self.assertEqual(len(actor.attempts["patroni"]), 1)
