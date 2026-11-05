import contextlib
import copy
import json
import io
from pathlib import PurePosixPath
import unittest
from unittest import mock
import subprocess
import sys

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

    def test_consumer_start_waits_for_leaf_commit(self):
        _, ram, _, docker, _, actor = fixture()
        docker.rows["rauth-test-patroni"]["State"]["Running"] = False
        docker.rows["rauth-test-app"]["State"]["Running"] = False
        actor.renewal_committing = lambda: True
        actor.tick()
        starts = [c for c in docker.calls if c[0] == "start"]
        self.assertNotIn(("start", "container-patroni"), starts)
        self.assertNotIn(("start", "container-app"), starts)  # identity is committed in place too
        actor.renewal_committing = lambda: False
        actor.tick()
        self.assertIn(("start", "container-patroni"), docker.calls)
        self.assertIn(("start", "container-app"), docker.calls)

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


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.ram, self.storage, self.docker, self.clock, _ = fixture()
        self.cfg["pki_renewal"] = {"directory": "/opt/rauth/rauth-test-state/pki-renewal"}
        self.actor = supervise.Supervisor(
            self.cfg,
            docker=self.docker,
            storage=self.storage,
            ram=self.ram,
            now=lambda: self.clock[0],
            wait=lambda _s: None,
        )
        self.actor.tick()
        self.files = {"restart-request.json": {"generation": 5}}
        self.written = []
        self.actor.handshake = lambda name: self.files.get(name)
        self.actor.finish_renewal = lambda g, r: self.written.append((g, r))
        self.roles = {"state-a": "sync_standby", "b": "leader", "c": "replica"}
        self.switchovers = []

        def patroni(ident, probe, *args):
            if probe is supervise.SWITCHOVER_PROBE:
                self.switchovers.append(args)
                self.roles[args[0]], self.roles[args[1]] = "sync_standby", "leader"
                return {"status": 503}
            members = [
                {"name": n, "role": r, "state": "running" if r == "leader" else "streaming", "lag": None if r == "leader" else 0}
                for n, r in self.roles.items()
            ]
            return {"self": "state-a", "members": members}

        self.docker.patroni = patroni

    def test_config_accepts_directory_inside_root_only(self):
        supervise.validate(self.cfg)
        bad = copy.deepcopy(self.cfg)
        bad["pki_renewal"]["directory"] = "/etc/elsewhere"
        with self.assertRaises(supervise.Fault):
            supervise.validate(bad)

    def test_replica_restarts_each_role_once_through_attested_start(self):
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [(5, "ok")])
        self.assertEqual(self.switchovers, [])
        self.assertIn(("stop", "container-patroni"), self.docker.calls)
        self.assertIn(("start", "container-patroni"), self.docker.calls)
        self.assertNotIn(("stop", "container-app"), self.docker.calls)
        self.assertIn("attest-patroni", self.ram.calls)

    def test_leader_switches_over_before_restart(self):
        self.roles = {"state-a": "leader", "b": "sync_standby", "c": "replica"}
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.switchovers, [("state-a", "b")])
        self.assertEqual(self.written, [(5, "ok")])

    def test_waits_while_unhealthy_and_skips_completed_generation(self):
        self.roles = {"state-a": "replica", "b": "leader"}
        self.actor.renewal()
        self.assertEqual(self.written, [])
        self.roles = {"state-a": "sync_standby", "b": "leader", "c": "replica"}
        self.files["restart-done.json"] = {"generation": 5, "result": "ok"}
        self.actor.renewal()
        self.assertEqual(self.written, [])

    def test_restart_failure_is_reported(self):
        self.docker.fail_start = True
        self.actor.renewal()
        self.assertEqual(self.written, [(5, "failed")])


class RenewalRoleGroupTests(RenewalTests):
    def test_identity_renewal_restarts_only_the_application(self):
        self.files = {"restart-request.json": {"generation": 9, "roles": ["app"]}}
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [(9, "ok")])
        self.assertIn(("stop", "container-app"), self.docker.calls)
        self.assertNotIn(("stop", "container-patroni"), self.docker.calls)

    def test_unknown_role_group_is_rejected(self):
        self.files = {"restart-request.json": {"generation": 3, "roles": ["tailscale"]}}
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [(3, "failed")])
        self.assertFalse([c for c in self.docker.calls if c[0] == "stop"])

    def test_non_string_role_entry_is_rejected(self):
        self.files = {"restart-request.json": {"generation": 4, "roles": [{}]}}
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [(4, "failed")])
        self.assertFalse([c for c in self.docker.calls if c[0] == "stop"])

    def test_configured_role_with_unusable_metadata_waits(self):
        self.files = {"restart-request.json": {"generation": 6, "roles": ["app"]}}
        self.actor.available.discard("app")
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [])
        self.assertFalse([c for c in self.docker.calls if c[0] == "stop"])

    def test_missing_patroni_metadata_does_not_skip_the_health_gate(self):
        self.actor.available.discard("patroni")
        self.roles = {"state-a": "replica", "b": "leader"}
        self.docker.calls.clear()
        self.actor.renewal()
        self.assertEqual(self.written, [])
        self.assertFalse([c for c in self.docker.calls if c[0] == "stop"])


class FailbackTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.ram, self.storage, self.docker, self.clock, _ = fixture()
        self.cfg["failback"] = {"hold_seconds": 600}
        self.actor = supervise.Supervisor(
            self.cfg, docker=self.docker, storage=self.storage, ram=self.ram,
            now=lambda: self.clock[0], wait=lambda _s: None,
        )
        self.actor.tick()
        self.roles = {"state-a": "replica", "b": "leader", "c": "sync_standby"}
        self.rest, self.count, self.promote = [], 1, True

        def patroni(ident, probe, *args):
            if probe is supervise.REST_PROBE:
                method, path, body = args
                self.rest.append((method, path, json.loads(body)))
                if path == "/config":
                    self.count = json.loads(body)["synchronous_node_count"]
                    if self.count == 2:
                        self.roles["state-a"] = "sync_standby"
                    return {"status": 200}
                if self.promote:
                    old = json.loads(body)["leader"]
                    self.roles[old], self.roles["state-a"] = "sync_standby", "leader"
                return {"status": 503}
            members = [
                {"name": n, "role": r, "state": "running" if r == "leader" else "streaming", "lag": None if r == "leader" else 0}
                for n, r in self.roles.items()
            ]
            return {"self": "state-a", "members": members}

        self.docker.patroni = patroni

    def test_config_validation(self):
        supervise.validate(self.cfg)
        for bad in (59, 86401, "600", True):
            cfg = copy.deepcopy(self.cfg)
            cfg["failback"]["hold_seconds"] = bad
            with self.assertRaises(supervise.Fault):
                supervise.validate(cfg)

    def test_fails_back_after_hold_and_restores_one_sync_standby(self):
        self.actor.failback()
        self.assertEqual(self.rest, [])  # hold starts
        self.clock[0] += 300
        self.actor.failback()
        self.assertEqual(self.rest, [])  # still holding
        self.clock[0] += 301
        self.actor.failback()
        self.assertEqual(
            self.rest,
            [
                ("PATCH", "/config", {"synchronous_node_count": 2}),
                ("POST", "/switchover", {"leader": "b", "candidate": "state-a"}),
                ("PATCH", "/config", {"synchronous_node_count": 1}),
            ],
        )
        self.assertEqual(self.roles["state-a"], "leader")
        self.assertEqual(self.count, 1)

    def test_sync_standby_switches_over_without_config_change(self):
        self.roles = {"state-a": "sync_standby", "b": "leader", "c": "replica"}
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(self.rest, [("POST", "/switchover", {"leader": "b", "candidate": "state-a"})])

    def test_leader_or_unhealthy_cluster_does_nothing(self):
        self.roles = {"state-a": "leader", "b": "sync_standby", "c": "replica"}
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.roles = {"state-a": "replica", "b": "leader"}  # two members only
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(self.rest, [])

    def test_transient_small_lag_does_not_reset_the_hold(self):
        lags = iter([0, 16384, 0, 4096, 0])
        real = self.docker.patroni

        def lagging(ident, probe, *args):
            out = real(ident, probe, *args)
            if probe is not supervise.REST_PROBE:
                lag = next(lags, 0)
                for m in out["members"]:
                    if m["name"] == "state-a":
                        m["lag"] = lag
            return out

        self.docker.patroni = lagging
        self.actor.failback()  # hold starts (lag 0)
        self.clock[0] += 300
        self.actor.failback()  # 16 KiB: still holding
        self.clock[0] += 301
        self.actor.failback()  # hold elapsed: fails back
        self.assertIn(("POST", "/switchover", {"leader": "b", "candidate": "state-a"}), self.rest)

    def test_sync_standby_with_lag_waits_for_zero_before_switchover(self):
        self.roles = {"state-a": "sync_standby", "b": "leader", "c": "replica"}
        lags = iter([0, 8192, 8192, 0])  # hold start, then lagging, then caught up
        real = self.docker.patroni

        def lagging(ident, probe, *args):
            out = real(ident, probe, *args)
            if probe is not supervise.REST_PROBE:
                lag = next(lags, 0)
                for m in out["members"]:
                    if m["name"] == "state-a":
                        m["lag"] = lag
            return out

        self.docker.patroni = lagging
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(self.rest, [("POST", "/switchover", {"leader": "b", "candidate": "state-a"})])
        self.assertEqual(next(lags, "done"), "done")  # polled until the lag reached zero

    def test_persistent_lag_never_switches_over(self):
        self.roles = {"state-a": "sync_standby", "b": "leader", "c": "replica"}
        real = self.docker.patroni

        def lagging(ident, probe, *args):
            out = real(ident, probe, *args)
            if probe is not supervise.REST_PROBE:
                for m in out["members"]:
                    if m["name"] == "state-a":
                        m["lag"] = 4096
            return out

        self.docker.patroni = lagging
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(self.rest, [])

    def test_large_or_unknown_lag_resets_the_hold(self):
        self.assertFalse(supervise.Supervisor.stable([
            {"name": "a", "role": "leader", "state": "running", "lag": None},
            {"name": "b", "role": "replica", "state": "streaming", "lag": 17 * 1024 * 1024},
            {"name": "c", "role": "sync_standby", "state": "streaming", "lag": 0},
        ]))
        self.assertFalse(supervise.Supervisor.stable([
            {"name": "a", "role": "leader", "state": "running", "lag": None},
            {"name": "b", "role": "replica", "state": "streaming", "lag": "unknown"},
            {"name": "c", "role": "sync_standby", "state": "streaming", "lag": 0},
        ]))

    def test_unhealthy_interval_resets_the_hold(self):
        self.actor.failback()
        self.clock[0] += 500
        self.roles["c"] = "replica"
        members = self.roles
        self.roles = {"state-a": "replica", "b": "leader"}
        self.actor.failback()  # unhealthy: hold reset
        self.roles = members
        self.actor.failback()  # hold restarts here
        self.clock[0] += 200
        self.actor.failback()
        self.assertEqual(self.rest, [])

    def test_unconfirmed_switchover_still_restores_sync_count_and_backs_off(self):
        self.promote = False
        self.actor.failback()
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(self.rest[-1], ("PATCH", "/config", {"synchronous_node_count": 1}))
        self.assertEqual(self.count, 1)
        calls = len(self.rest)
        self.clock[0] += 601
        self.actor.failback()
        self.assertEqual(len(self.rest), calls)  # retry waits for the back-off

    def test_failed_restore_is_retried_before_anything_else(self):
        self.actor.failback()
        self.clock[0] += 601
        real = self.docker.patroni

        def refuse_restore(ident, probe, *args):
            if probe is supervise.REST_PROBE and args[1] == "/config" and json.loads(args[2])["synchronous_node_count"] == 1:
                return {"status": 500}
            return real(ident, probe, *args)

        self.docker.patroni = refuse_restore
        self.actor.failback()
        self.assertTrue(self.actor.failback_restore)
        self.docker.patroni = real
        self.actor.failback()
        self.assertFalse(self.actor.failback_restore)
        self.assertEqual(self.count, 1)


class BackupScheduleTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.ram, self.storage, self.docker, self.clock, _ = fixture()
        self.cfg["backup"] = {"interval_hours": 6, "keep": 4}
        self.actor = supervise.Supervisor(
            self.cfg, docker=self.docker, storage=self.storage, ram=self.ram,
            now=lambda: self.clock[0], wait=lambda _s: None,
        )
        self.actor.tick()
        self.healthy = True
        self.actor.cluster_healthy = lambda: self.healthy
        self.spawned = []

        class Process:
            def __init__(proc):
                proc.returncode, proc.done = None, False
                proc.killed, proc.waited = False, False

            def poll(proc):
                return proc.returncode if proc.done else None

            def kill(proc):
                proc.killed = True
                proc.returncode, proc.done = -9, True

            def wait(proc, timeout=None):
                proc.waited = True
                return proc.returncode

            def output(proc):
                return b'{"backup": {"verified": true}, "kept": []}'

        def spawn(ident, keep):
            proc = Process()
            self.spawned.append((ident, keep, proc))
            return proc

        self.docker.spawn_backup = spawn

    def test_schedule_validation(self):
        supervise.validate(self.cfg)
        for bad in ({"interval_hours": 0, "keep": 4}, {"interval_hours": 6, "keep": 0}, {"interval_hours": 6}):
            cfg = copy.deepcopy(self.cfg)
            cfg["backup"] = bad
            with self.assertRaises(supervise.Fault):
                supervise.validate(cfg)

    def test_runs_after_stagger_without_blocking_and_reschedules(self):
        self.actor.backup()
        self.assertEqual(self.spawned, [])
        self.clock[0] = self.actor.backup_due
        self.actor.backup()
        self.assertEqual([(i, k) for i, k, _ in self.spawned], [("container-patroni", 4)])
        self.actor.backup()  # still running: no second process
        self.assertEqual(len(self.spawned), 1)
        proc = self.spawned[0][2]
        proc.returncode, proc.done = 0, True
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.actor.backup()
        self.assertIn('"completed"', out.getvalue())
        self.assertEqual(self.actor.backup_due, self.clock[0] + 6 * 3600)

    def test_unhealthy_cluster_defers(self):
        self.healthy = False
        self.clock[0] = self.actor.backup_due
        self.actor.backup()
        self.assertEqual(self.spawned, [])
        self.assertEqual(self.actor.backup_due, self.clock[0] + 300)

    def test_backup_past_four_hours_is_killed(self):
        self.clock[0] = self.actor.backup_due
        self.actor.backup()
        proc = self.spawned[0][2]
        self.clock[0] += 4 * 3600
        self.actor.backup()  # exactly at the limit: still allowed
        self.assertFalse(proc.killed)
        self.clock[0] += 1
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.actor.backup()
        self.assertTrue(proc.killed and proc.waited)
        self.assertIsNone(self.actor.backup_process)
        self.assertIn('"timed_out"', out.getvalue())

    def test_shutdown_kills_running_backup(self):
        self.clock[0] = self.actor.backup_due
        self.actor.backup()
        proc = self.spawned[0][2]
        self.actor.run(once=True)
        self.assertTrue(proc.killed and proc.waited)

    def test_drained_child_output_never_blocks_the_child(self):
        # Far more than a pipe buffer: without concurrent draining the child
        # would block on write and never exit.
        child = supervise.Drained(
            subprocess.Popen(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * (4 * 1024 * 1024))"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        )
        self.assertEqual(child.wait(60), 0)
        self.assertEqual(child.output(), b"x" * supervise.LIMIT)
