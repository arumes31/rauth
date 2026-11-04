import datetime
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    import pki_renew
except ImportError:  # pragma: no cover - CI installs the hash-locked test deps
    pki_renew = None

SCOPE = "rauth-test-state-20261102"
NODES = {"hodus": "100.72.210.48", "nl": "100.124.226.67", "pi3": "100.84.64.76"}
NOW = datetime.datetime(2026, 12, 20, tzinfo=datetime.timezone.utc)


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)


def keypem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def make_ca(role):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RAuth production physical %s CA v2" % role)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=60)).not_valid_after(NOW + datetime.timedelta(days=10000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(ca, cn, ips=(), dns=(), server=True, client=False, days_left=20, key=None):
    cert, cakey = ca
    key = key or ec.generate_private_key(ec.SECP256R1())
    usages = ([ExtendedKeyUsageOID.SERVER_AUTH] if server else []) + ([ExtendedKeyUsageOID.CLIENT_AUTH] if client else [])
    b = (
        x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=70)).not_valid_after(NOW + datetime.timedelta(days=days_left))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(usages), critical=True)
    )
    names = [x509.IPAddress(__import__("ipaddress").ip_address(i)) for i in ips] + [x509.DNSName(d) for d in dns]
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return b.sign(cakey, hashes.SHA256()), key


@unittest.skipIf(pki_renew is None, "cryptography is not installed")
class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.cas = {r: make_ca(r) for r in ("sql", "rest", "dcs-client")}
        for role, (cert, key) in cls.cas.items():
            Path(cls.dir.name, role + ".crt").write_bytes(pem(cert))
            Path(cls.dir.name, role + ".key").write_bytes(keypem(key))
        cls.authority = pki_renew.Authority(cls.dir.name)
        cls.policy = {"scope": SCOPE, "nodes": NODES}

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def csr(self, cert, key=None):
        key = key or ec.generate_private_key(ec.SECP256R1())
        req = x509.CertificateSigningRequestBuilder().subject_name(cert.subject).sign(key, hashes.SHA256())
        return pem(req).decode(), key

    def issue(self, node, cert, csr):
        return pki_renew.check_and_issue(self.authority, self.policy, node, pem(cert).decode(), csr, now=NOW)

    def test_renewal_copies_identity_with_fresh_key(self):
        cert, _ = make_leaf(self.cas["sql"], "nl-sql-server", ["100.124.226.67"], [SCOPE + ".sql.rauth.internal"])
        csr, key = self.csr(cert)
        new = x509.load_pem_x509_certificate(self.issue("nl", cert, csr).encode())
        self.assertEqual(new.subject, cert.subject)
        self.assertEqual(pki_renew.sans(new), pki_renew.sans(cert))
        self.assertEqual(pki_renew.eku(new), pki_renew.eku(cert))
        self.assertEqual(pki_renew.spki(new.public_key()), pki_renew.spki(key.public_key()))
        self.assertTrue(pki_renew.signed_by(new, self.cas["sql"][0]))
        self.assertEqual((pki_renew.expiry(new) - NOW).days, 90)

    def test_refusals(self):
        good, goodkey = make_leaf(self.cas["sql"], "nl-sql-server", ["100.124.226.67"], [SCOPE + ".sql.rauth.internal"])
        cases = {
            "identity_not_owned_by_node": ("pi3", good, self.csr(good)[0]),
            "unknown_node": ("oracle", good, self.csr(good)[0]),
            "csr_key_reused": ("nl", good, self.csr(good, goodkey)[0]),
        }
        foreign_ip, _ = make_leaf(self.cas["sql"], "nl-sql-server", ["100.84.64.76"])
        cases["subject_alternative_name_not_owned_by_node"] = ("nl", foreign_ip, self.csr(foreign_ip)[0])
        foreign_dns, _ = make_leaf(self.cas["sql"], "nl-sql-server", [], ["evil.example"])
        cases["subject_alternative_name_not_owned_by_node "] = ("nl", foreign_dns, self.csr(foreign_dns)[0])
        expired, _ = make_leaf(self.cas["sql"], "nl-sql-server", days_left=-1)
        cases["current_not_valid_now"] = ("nl", expired, self.csr(expired)[0])
        stranger, _ = make_leaf(make_ca("sql"), "nl-sql-server")
        cases["current_not_issued_by_authority"] = ("nl", stranger, self.csr(stranger)[0])
        other, _ = make_leaf(self.cas["sql"], "nl-rest-server")
        cases["csr_invalid_or_subject_mismatch"] = ("nl", good, self.csr(other)[0])
        for reason, (node, cert, csr) in cases.items():
            with self.subTest(reason):
                with self.assertRaises(pki_renew.Refused) as raised:
                    self.issue(node, cert, csr)
                self.assertEqual(str(raised.exception), reason.strip())


@unittest.skipIf(pki_renew is None, "cryptography is not installed")
class StateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.state = pki_renew.IssuerState(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_one_node_at_a_time_and_failures_block(self):
        lease = self.state.begin("nl", 1000)
        with self.assertRaises(pki_renew.Refused):
            self.state.begin("pi3", 1001)
        self.assertTrue(self.state.holds("nl", lease, 1002))
        self.assertFalse(self.state.holds("pi3", lease, 1002))
        # A stale lease no longer blocks other nodes.
        lease2 = self.state.begin("pi3", 1000 + pki_renew.LEASE_SECONDS + 1)
        self.state.done("pi3", lease2, "failed", 20000)
        with self.assertRaises(pki_renew.Refused) as raised:
            self.state.begin("nl", 20001)
        self.assertEqual(str(raised.exception), "rollout_blocked_by_failure")

    def test_aborted_rollout_does_not_block_and_daily_limit_applies(self):
        lease = self.state.begin("nl", 10)
        self.state.done("nl", lease, "aborted", 11)
        self.state.begin("pi3", 12)
        for i in range(pki_renew.DAILY_ISSUE_LIMIT):
            self.state.record("pi3", "pi3-server", "f", 100 + i)
        with self.assertRaises(pki_renew.Refused):
            self.state.record("pi3", "pi3-server", "f", 200)
        self.state.record("pi3", "pi3-server", "f", 100 + 86401)


@unittest.skipIf(pki_renew is None, "cryptography is not installed")
class AgentTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "authority").mkdir()
        (root / "pki").mkdir()
        (root / "state").mkdir()
        (root / "issuer").mkdir()
        self.root = root
        self.cas = {r: make_ca(r) for r in ("sql", "rest")}
        for role, (cert, key) in self.cas.items():
            (root / "authority" / (role + ".crt")).write_bytes(pem(cert))
            (root / "authority" / (role + ".key")).write_bytes(keypem(key))
        (root / "pki" / "trust.crt").write_bytes(b"".join(pem(c) for c, _ in self.cas.values()))
        sql, sqlkey = make_leaf(self.cas["sql"], "nl-sql-server", ["100.124.226.67"], [SCOPE + ".sql.rauth.internal"])
        client, clientkey = make_leaf(self.cas["rest"], "nl-rest-client", server=False, client=True)
        health, healthkey = make_leaf(self.cas["rest"], "nl-health", server=False, client=True)
        for name, cert, key in (("sql-server", sql, sqlkey), ("rest-client", client, clientkey)):
            (root / "pki" / (name + ".crt")).write_bytes(pem(cert))
            (root / "pki" / (name + ".key")).write_bytes(keypem(key))
        (root / "pki" / "health.pem").write_bytes(pem(health) + keypem(healthkey))
        (root / "pki" / "observer.crt").write_bytes(pem(client))
        (root / "pki" / "observer.key").write_bytes(keypem(clientkey))
        p = str(root / "pki")
        self.cfg = {
            "node": "nl",
            "state_dir": str(root / "state"),
            "trust_bundles": [p + "/trust.crt"],
            "leaves": [
                {"name": "patroni/sql-server", "cert": p + "/sql-server.crt", "key": p + "/sql-server.key"},
                {"name": "patroni/rest-client", "cert": p + "/rest-client.crt", "key": p + "/rest-client.key"},
                {"name": "router/health-client", "pem": p + "/health.pem"},
            ],
            "copies": [{"from": "patroni/rest-client", "cert": p + "/observer.crt", "key": p + "/observer.key"}],
            "renew_before_days": 30,
            "restart_timeout": 60,
        }
        self.authority = pki_renew.Authority(root / "authority")
        self.state = pki_renew.IssuerState(root / "issuer")
        self.tamper = None

    def tearDown(self):
        self.dir.cleanup()

    def client(self, path, body):
        now = time.time()
        if path == "/v1/begin":
            return {"lease": self.state.begin("nl", now)}
        if path == "/v1/renew":
            assert self.state.holds("nl", body["lease"], now)
            out = pki_renew.check_and_issue(self.authority, {"scope": SCOPE, "nodes": NODES}, "nl", body["current"], body["csr"], now=NOW)
            return {"certificate": self.tamper(out) if self.tamper else out}
        self.state.done("nl", body["lease"], body["result"], now)
        return {"ok": True}

    def agent(self, healthy=True, supervisor_result="ok"):
        def sleep(_):
            request = json.loads((self.root / "state" / "restart-request.json").read_text())
            pki_renew.atomic_write(self.root / "state" / "restart-done.json", json.dumps({"generation": request["generation"], "result": supervisor_result}).encode())

        members = [{"role": "leader", "state": "running"}, {"role": "sync_standby", "state": "streaming", "lag": 0}, {"role": "replica", "state": "streaming", "lag": 0}]
        return pki_renew.Agent(self.cfg, client=self.client, cluster=lambda: members if healthy else members[:2], now=lambda: NOW, sleep=sleep)

    def test_full_cycle_rewrites_in_place_and_requests_restart(self):
        inodes = {p: os.stat(p).st_ino for p in (self.root / "pki").iterdir()}
        old_key = (self.root / "pki" / "sql-server.key").read_bytes()
        self.assertEqual(self.agent().renew(), "renewed")
        for p, ino in inodes.items():
            self.assertEqual(os.stat(p).st_ino, ino)
        self.assertNotEqual((self.root / "pki" / "sql-server.key").read_bytes(), old_key)
        new = x509.load_pem_x509_certificate((self.root / "pki" / "sql-server.crt").read_bytes())
        key = serialization.load_pem_private_key((self.root / "pki" / "sql-server.key").read_bytes(), None)
        self.assertEqual(pki_renew.spki(new.public_key()), pki_renew.spki(key.public_key()))
        health = (self.root / "pki" / "health.pem").read_bytes()
        self.assertIn(b"BEGIN CERTIFICATE", health)
        self.assertIn(b"PRIVATE KEY", health)
        self.assertEqual((self.root / "pki" / "observer.crt").read_bytes(), (self.root / "pki" / "rest-client.crt").read_bytes())
        self.assertEqual(len(list((self.root / "state").glob("backup-*/*"))), 7)
        self.assertIsNone(self.state.load()["lease"])
        self.assertEqual(self.agent().renew(), "fresh")

    def test_unhealthy_cluster_waits_and_bad_issuer_aborts_without_changes(self):
        before = {p.name: p.read_bytes() for p in (self.root / "pki").iterdir()}
        self.assertEqual(self.agent(healthy=False).renew(), "cluster_not_healthy")
        other = make_leaf(self.cas["sql"], "nl-sql-server", ["100.84.64.76"])[0]
        self.tamper = lambda _pem: pem(other).decode()
        with self.assertRaises(pki_renew.Refused):
            self.agent().renew()
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "pki").iterdir()})
        self.assertIsNone(self.state.load()["lease"])
        self.assertIsNone(self.state.load()["blocked"])

    def test_failed_restart_blocks_rollout(self):
        self.assertEqual(self.agent(supervisor_result="failed").renew(), "restart_failed")
        self.assertEqual(self.state.load()["blocked"]["node"], "nl")

    def test_resume_after_agent_restart_reports_outcome(self):
        lease = self.state.begin("nl", time.time())
        pki_renew.atomic_write(self.root / "state" / "restart-request.json", json.dumps({"generation": 7, "lease": lease}).encode())
        self.assertEqual(self.agent().renew(), "resumed_ok")
        self.assertIsNone(self.state.load()["lease"])


@unittest.skipIf(pki_renew is None, "cryptography is not installed")
class TransportTests(unittest.TestCase):
    def test_mutual_tls_identifies_node_by_rest_client_certificate(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "authority").mkdir()
            rest = make_ca("rest")
            (d / "authority" / "rest.crt").write_bytes(pem(rest[0]))
            (d / "authority" / "rest.key").write_bytes(keypem(rest[1]))
            (d / "ca.crt").write_bytes(pem(rest[0]))
            now = datetime.datetime.now(datetime.timezone.utc)
            global NOW
            saved, NOW = NOW, now
            try:
                server, skey = make_leaf(rest, "hodus-rest-server", ["127.0.0.1"])
                good, gkey = make_leaf(rest, "nl-rest-client", server=False, client=True)
                bad, bkey = make_leaf(rest, "nl-health", server=False, client=True)
            finally:
                NOW = saved
            for name, c, k in (("server", server, skey), ("good", good, gkey), ("bad", bad, bkey)):
                (d / (name + ".crt")).write_bytes(pem(c))
                (d / (name + ".key")).write_bytes(keypem(k))
            issuer = pki_renew.make_issuer({"listen": "127.0.0.1:0", "authority_dir": str(d / "authority"), "state_dir": str(d), "scope": SCOPE, "nodes": NODES, "server_cert": str(d / "server.crt"), "server_key": str(d / "server.key"), "client_ca": str(d / "ca.crt")})
            threading.Thread(target=issuer.serve_forever, daemon=True).start()
            try:
                endpoint = "127.0.0.1:%d" % issuer.server_address[1]
                base = {"node": "nl", "issuer": endpoint, "issuer_ca": str(d / "ca.crt"), "state_dir": str(d)}
                agent = pki_renew.Agent({**base, "client_cert": str(d / "good.crt"), "client_key": str(d / "good.key")})
                self.assertTrue(agent.client("/v1/begin", {})["lease"])
                stranger = pki_renew.Agent({**base, "client_cert": str(d / "bad.crt"), "client_key": str(d / "bad.key")})
                with self.assertRaises(pki_renew.Refused):
                    stranger.client("/v1/begin", {})
            finally:
                issuer.shutdown()
                issuer.server_close()


CLUSTER = "8389748f-4b47-4d29-832f-5e1155639e3f"
APP_NODES = {"hodus": "100.72.210.48", "oracle": "100.83.175.79"}


def make_identity_ca():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RAuth production node CA " + CLUSTER)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=10000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, None)
    )
    return cert, key


def make_identity(ca, node, ip, uri=None, key=None, days_left=20):
    import ipaddress

    from cryptography.hazmat.primitives.asymmetric import ed25519

    cert, cakey = ca
    key = key or ed25519.Ed25519PrivateKey.generate()
    uri = uri or "spiffe://rauth/%s/node/%s" % (CLUSTER, "11111111-2222-4333-8444-555555555555")
    leaf = (
        x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RAuth production " + node)]))
        .issuer_name(cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=70)).not_valid_after(NOW + datetime.timedelta(days=days_left))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip)), x509.UniformResourceIdentifier(uri)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(cakey, None)
    )
    return leaf, key


def identity_csr(cert, key):
    return pem(x509.CertificateSigningRequestBuilder().subject_name(cert.subject).sign(key, None)).decode()


@unittest.skipIf(pki_renew is None, "cryptography is not installed")
class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.ca = make_identity_ca()
        (d / "node-ca.crt").write_bytes(pem(self.ca[0]))
        (d / "node-ca.key").write_bytes(keypem(self.ca[1]))
        self.authority = pki_renew.IdentityAuthority({"ca_cert": str(d / "node-ca.crt"), "ca_key": str(d / "node-ca.key"), "nodes": APP_NODES, "cluster_id": CLUSTER})
        self.d = d

    def tearDown(self):
        self.dir.cleanup()

    def test_same_key_renewal_and_refusals(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        leaf, key = make_identity(self.ca, "oracle", "100.83.175.79")
        new = x509.load_pem_x509_certificate(pki_renew.check_identity(self.authority, "oracle", pem(leaf).decode(), identity_csr(leaf, key), now=NOW).encode())
        self.assertEqual(pki_renew.spki(new.public_key()), pki_renew.spki(key.public_key()))
        self.assertEqual(pki_renew.uris(new), pki_renew.uris(leaf))
        self.assertGreater(pki_renew.expiry(new), pki_renew.expiry(leaf))
        other_key = ed25519.Ed25519PrivateKey.generate()
        foreign, fkey = make_identity(self.ca, "oracle", "100.83.175.79", uri="spiffe://rauth/other/node/x")
        cases = {
            "identity_key_must_not_change": ("oracle", leaf, identity_csr(leaf, other_key)),
            "identity_not_owned_by_node": ("hodus", leaf, identity_csr(leaf, key)),
            "identity_uri_not_in_cluster": ("oracle", foreign, identity_csr(foreign, fkey)),
        }
        for reason, (node, cert, csr) in cases.items():
            with self.subTest(reason), self.assertRaises(pki_renew.Refused) as raised:
                pki_renew.check_identity(self.authority, node, pem(cert).decode(), csr, now=NOW)
            self.assertEqual(str(raised.exception), reason)

    def test_application_only_agent_renews_identity_and_requests_app_restart(self):
        leaf, key = make_identity(self.ca, "oracle", "100.83.175.79")
        (self.d / "state").mkdir()
        (self.d / "node.crt").write_bytes(pem(leaf))
        (self.d / "node.key").write_bytes(keypem(key))
        state = pki_renew.IssuerState(self.d)

        def client(path, body):
            if path == "/v1/begin":
                return {"lease": state.begin("oracle", time.time())}
            if path == "/v1/identity":
                return {"certificate": pki_renew.check_identity(self.authority, "oracle", body["current"], body["csr"], now=NOW)}
            state.done("oracle", body["lease"], body["result"], time.time())
            return {}

        requests = []

        def sleep(_):
            request = json.loads((self.d / "state" / "restart-request.json").read_text())
            requests.append(request)
            pki_renew.atomic_write(self.d / "state" / "restart-done.json", json.dumps({"generation": request["generation"], "result": "ok"}).encode())

        cfg = {"node": "oracle", "state_dir": str(self.d / "state"), "identity": {"cert": str(self.d / "node.crt"), "key": str(self.d / "node.key"), "ca": str(self.d / "node-ca.crt")}}
        agent = pki_renew.Agent(cfg, client=client, now=lambda: NOW, sleep=sleep)
        key_before = (self.d / "node.key").read_bytes()
        self.assertEqual(agent.renew(), "renewed")
        self.assertEqual(requests[0]["roles"], ["app"])
        self.assertEqual((self.d / "node.key").read_bytes(), key_before)
        self.assertGreater(agent.days_left("identity"), 80)

    def test_node_identity_authenticates_to_identity_route_only(self):
        global NOW
        saved, NOW = NOW, datetime.datetime.now(datetime.timezone.utc)
        try:
            rest = make_ca("rest")
            ca = make_identity_ca()
            server, skey = make_leaf(rest, "hodus-rest-server", ["127.0.0.1"])
            leaf, key = make_identity(ca, "oracle", "100.83.175.79")
        finally:
            NOW = saved
        d = self.d
        (d / "authority").mkdir()
        (d / "authority" / "rest.crt").write_bytes(pem(rest[0]))
        (d / "authority" / "rest.key").write_bytes(keypem(rest[1]))
        (d / "rest-ca.crt").write_bytes(pem(rest[0]))
        (d / "id-ca.crt").write_bytes(pem(ca[0]))
        (d / "id-ca.key").write_bytes(keypem(ca[1]))
        for name, c, k in (("server", server, skey), ("node", leaf, key)):
            (d / (name + ".crt")).write_bytes(pem(c))
            (d / (name + ".key")).write_bytes(keypem(k))
        issuer = pki_renew.make_issuer({"listen": "127.0.0.1:0", "authority_dir": str(d / "authority"), "state_dir": str(d), "scope": SCOPE, "nodes": NODES, "server_cert": str(d / "server.crt"), "server_key": str(d / "server.key"), "client_ca": str(d / "rest-ca.crt"), "identity": {"ca_cert": str(d / "id-ca.crt"), "ca_key": str(d / "id-ca.key"), "nodes": APP_NODES, "cluster_id": CLUSTER}})
        threading.Thread(target=issuer.serve_forever, daemon=True).start()
        try:
            agent = pki_renew.Agent({"node": "oracle", "state_dir": str(d), "issuer": "127.0.0.1:%d" % issuer.server_address[1], "issuer_ca": str(d / "rest-ca.crt"), "client_cert": str(d / "node.crt"), "client_key": str(d / "node.key")})
            lease = agent.client("/v1/begin", {})["lease"]
            csr = identity_csr(leaf, key)
            renewed = agent.client("/v1/identity", {"lease": lease, "current": pem(leaf).decode(), "csr": csr})["certificate"]
            self.assertIn("BEGIN CERTIFICATE", renewed)
            with self.assertRaises(pki_renew.Refused):
                agent.client("/v1/renew", {"lease": lease, "current": pem(leaf).decode(), "csr": csr})
        finally:
            issuer.shutdown()
            issuer.server_close()


if __name__ == "__main__":
    unittest.main()
