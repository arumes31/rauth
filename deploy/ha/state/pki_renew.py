#!/usr/bin/env python3
"""Automatic renewal of the physical HA leaf certificates (pull model).

issuer: runs only on the CA master. Holds the CA keys read-only and serves
        TLS 1.3 mutual-TLS renewal on the node's service IP. It never mints a
        new identity: a request must present an unexpired leaf issued by one
        of its CAs, whose CN/SAN belong to the authenticated node, plus a CSR
        with a fresh key. The renewed leaf copies subject, SAN and extensions.
        One node renews at a time (lease); a failed rollout blocks the rest.
agent:  runs on every node. When any leaf has <= renew_before_days left and
        the cluster is healthy, it obtains a lease, renews every leaf, verifies
        each result, writes the files in place (inode/owner/mode preserved),
        then asks the host supervisor for a leader-aware rolling restart via a
        fsynced handshake file and reports the outcome to the issuer.
Application node identities (the enrolled node.crt used for the private
cluster transport) renew on the SAME key, so controller SPKI pins and node
enrollments stay valid; only the application container restarts.
CA private keys never leave the master; agents generate their own keys.
"""

import argparse
import datetime
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import threading
import time
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

LIMIT = 64 * 1024
LEAF_SUFFIXES = ("server", "peer", "etcd-loopback", "dcs-client", "rest-client", "rest-server", "sql-server", "health")
LEASE_SECONDS = 3 * 3600
DAILY_ISSUE_LIMIT = 32


class Refused(Exception):
    """A renewal request violates policy. The message is a static reason."""


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def expiry(cert):
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def start_of(cert):
    value = getattr(cert, "not_valid_before_utc", None)
    return value if value is not None else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def read_private(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError("unsafe file: " + str(path))
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def load_json(path):
    return json.loads(read_private(path))


def fsync_dir(path):
    if os.name == "nt":  # model tests only; the runtime is Linux
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


MARKER = "commit-active.json"


def write_all(fd, body):
    view = memoryview(body)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def atomic_write(path, body, mode=0o600):
    path = Path(path)
    tmp = path.with_name(".pending-" + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode)
    try:
        write_all(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    fsync_dir(path.parent)


def rewrite_in_place(path, body):
    """Keep inode/owner/mode so bind mounts and host-guard witnesses stay valid."""
    before = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not a regular file: " + str(path))
    fd = os.open(path, os.O_WRONLY | NOFOLLOW)
    try:
        if os.fstat(fd).st_ino != before.st_ino:
            raise ValueError("file replaced during rewrite")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        write_all(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    after = os.stat(path, follow_symlinks=False)
    if (after.st_ino, after.st_uid, after.st_gid, after.st_mode) != (before.st_ino, before.st_uid, before.st_gid, before.st_mode):
        raise ValueError("file identity changed: " + str(path))
    if read_private(path) != body:
        raise ValueError("rewrite verification failed: " + str(path))


def pem_certs(raw):
    out = []
    marker = b"-----END CERTIFICATE-----"
    for part in raw.split(marker)[:-1]:
        out.append(x509.load_pem_x509_certificate(part.strip() + b"\n" + marker + b"\n"))
    return out


def sans(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set(), set(), 0
    ips = {str(i) for i in ext.get_values_for_type(x509.IPAddress)}
    dns = set(ext.get_values_for_type(x509.DNSName))
    return ips, dns, len(list(ext)) - len(ips) - len(dns)


def eku(cert):
    try:
        return {o.dotted_string for o in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value}
    except x509.ExtensionNotFound:
        return set()


def common_name(cert):
    values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if len(values) == 1 else ""


def signed_by(cert, ca):
    if cert.issuer != ca.subject:
        return False
    try:
        key = ca.public_key()
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# ---------------------------------------------------------------- issuer policy


class Authority:
    def __init__(self, directory):
        self.cas = []
        for crt in sorted(Path(directory).glob("*.crt")):
            cert = x509.load_pem_x509_certificate(read_private(crt))
            key = serialization.load_pem_private_key(read_private(crt.with_suffix(".key")), None)
            if spki(cert.public_key()) != spki(key.public_key()):
                raise ValueError("CA key mismatch: " + crt.name)
            self.cas.append((cert, key))
        if not self.cas:
            raise ValueError("no CA material")

    def issuer_of(self, cert):
        for ca, key in self.cas:
            if signed_by(cert, ca):
                return ca, key
        return None, None


def check_and_issue(authority, policy, node, current_pem, csr_pem, now=None, leaf_days=90):
    """Return a renewed PEM leaf, or raise Refused."""
    now = now or utcnow()
    if node not in policy["nodes"]:
        raise Refused("unknown_node")
    try:
        current = x509.load_pem_x509_certificate(current_pem.encode())
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, TypeError, AttributeError):
        raise Refused("malformed_request") from None
    ca, ca_key = authority.issuer_of(current)
    if ca is None:
        raise Refused("current_not_issued_by_authority")
    if not start_of(current) <= now <= expiry(current):
        raise Refused("current_not_valid_now")
    if common_name(current) not in {node + "-" + s for s in LEAF_SUFFIXES}:
        raise Refused("identity_not_owned_by_node")
    ips, dns, other = sans(current)
    scope = policy["scope"]
    if other or not ips <= {policy["nodes"][node]} or not dns <= {node + ".rest." + scope + ".internal", scope + ".sql.rauth.internal"}:
        raise Refused("subject_alternative_name_not_owned_by_node")
    if not csr.is_signature_valid or csr.subject != current.subject:
        raise Refused("csr_invalid_or_subject_mismatch")
    public = csr.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256r1":
        raise Refused("csr_key_type")
    if spki(public) == spki(current.public_key()):
        raise Refused("csr_key_reused")
    builder = (
        x509.CertificateBuilder()
        .subject_name(current.subject)
        .issuer_name(ca.subject)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(min(now + datetime.timedelta(days=leaf_days), expiry(ca)))
    )
    for ext in current.extensions:
        value = ext.value
        if isinstance(value, x509.SubjectKeyIdentifier):
            value = x509.SubjectKeyIdentifier.from_public_key(public)
        elif isinstance(value, x509.AuthorityKeyIdentifier):
            value = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key())
        builder = builder.add_extension(value, ext.critical)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def uris(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return ext.get_values_for_type(x509.UniformResourceIdentifier)


class IdentityAuthority:
    """Application node CA (often Ed25519) used for same-key identity renewal."""

    def __init__(self, cfg):
        self.ca = x509.load_pem_x509_certificate(read_private(cfg["ca_cert"]))
        self.key = serialization.load_pem_private_key(read_private(cfg["ca_key"]), None)
        if spki(self.ca.public_key()) != spki(self.key.public_key()):
            raise ValueError("identity CA key mismatch")
        self.nodes, self.cluster = cfg["nodes"], cfg["cluster_id"]

    def name_of(self, cert):
        """Node name for a certificate issued by this CA, by its only IP SAN."""
        if not signed_by(cert, self.ca):
            return None
        ips, dns, other = sans(cert)
        if len(ips) != 1 or dns:
            return None
        return next((n for n, ip in self.nodes.items() if ip in ips), None)


def check_identity(authority, node, current_pem, csr_pem, now=None, leaf_days=90):
    """Re-issue an application node identity on its existing key."""
    now = now or utcnow()
    try:
        current = x509.load_pem_x509_certificate(current_pem.encode())
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, TypeError, AttributeError):
        raise Refused("malformed_request") from None
    if authority.name_of(current) != node:
        raise Refused("identity_not_owned_by_node")
    if not start_of(current) <= now <= expiry(current):
        raise Refused("current_not_valid_now")
    prefix = "spiffe://rauth/" + authority.cluster + "/node/"
    names = uris(current)
    if len(names) != 1 or not names[0].startswith(prefix):
        raise Refused("identity_uri_not_in_cluster")
    if not csr.is_signature_valid or csr.subject != current.subject:
        raise Refused("csr_invalid_or_subject_mismatch")
    if spki(csr.public_key()) != spki(current.public_key()):
        # Same key: controller pins and enrollments are bound to this SPKI.
        raise Refused("identity_key_must_not_change")
    builder = (
        x509.CertificateBuilder()
        .subject_name(current.subject)
        .issuer_name(authority.ca.subject)
        .public_key(current.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(min(now + datetime.timedelta(days=leaf_days), expiry(authority.ca)))
    )
    for ext in current.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    algorithm = None if isinstance(authority.key, (ed25519.Ed25519PrivateKey,)) else hashes.SHA256()
    return builder.sign(authority.key, algorithm).public_bytes(serialization.Encoding.PEM).decode()


class IssuerState:
    """Lease, block and rate state; one fsynced JSON document."""

    def __init__(self, directory):
        self.path = Path(directory) / "issuer-state.json"
        self.audit = Path(directory) / "issued.jsonl"
        self.lock = threading.Lock()

    def load(self):
        try:
            return json.loads(read_private(self.path))
        except FileNotFoundError:
            return {"lease": None, "blocked": None, "issued": []}

    def save(self, state):
        atomic_write(self.path, json.dumps(state, indent=1).encode())

    def begin(self, node, now):
        with self.lock:
            s = self.load()
            if s["blocked"]:
                raise Refused("rollout_blocked_by_failure")
            lease = s["lease"]
            if lease and lease["node"] != node and now - lease["since"] < LEASE_SECONDS:
                raise Refused("another_node_renewing")
            s["lease"] = {"node": node, "since": now, "id": uuid.uuid4().hex}
            self.save(s)
            return s["lease"]["id"]

    def holds(self, node, lease_id, now):
        s = self.load()
        lease = s["lease"]
        return bool(lease and lease["node"] == node and lease["id"] == lease_id and now - lease["since"] < LEASE_SECONDS)

    def record(self, node, cn, fingerprint, now):
        with self.lock:
            s = self.load()
            s["issued"] = [i for i in s["issued"] if now - i["at"] < 86400]
            if sum(1 for i in s["issued"] if i["node"] == node) >= DAILY_ISSUE_LIMIT:
                raise Refused("daily_issue_limit")
            s["issued"].append({"node": node, "at": now})
            self.save(s)
            fd = os.open(self.audit, os.O_WRONLY | os.O_CREAT | os.O_APPEND | NOFOLLOW, 0o600)
            try:
                os.write(fd, (json.dumps({"at": now, "node": node, "cn": cn, "sha256": fingerprint}) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)

    def done(self, node, lease_id, result, now):
        with self.lock:
            s = self.load()
            lease = s["lease"]
            if not lease or lease["node"] != node or lease["id"] != lease_id:
                raise Refused("no_matching_lease")
            s["lease"] = None
            if result == "failed":
                s["blocked"] = {"node": node, "at": now}
            self.save(s)


def peer_identity(sock, identity=None):
    """('physical', node) for a REST client leaf, ('app', node) for a node identity."""
    cert = x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
    if identity is not None:
        name = identity.name_of(cert)
        if name is not None:
            return "app", name
    cn = common_name(cert)
    if cn.endswith("-rest-client"):
        return "physical", cn[: -len("-rest-client")]
    return None, None


def make_issuer(cfg):
    authority = Authority(cfg["authority_dir"])
    identity = IdentityAuthority(cfg["identity"]) if "identity" in cfg else None
    state = IssuerState(cfg["state_dir"])
    policy = {"scope": cfg["scope"], "nodes": cfg["nodes"]}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(cfg["server_cert"], cfg["server_key"])
    ctx.load_verify_locations(cfg["client_ca"])
    if identity is not None:
        ctx.load_verify_locations(cfg["identity"]["ca_cert"])

    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 30
        server_version = "rauth-pki-issuer"

        def setup(self):
            # Handshake per connection thread so one stalled peer cannot block.
            self.request.settimeout(30)
            self.request.do_handshake()
            super().setup()

        def log_message(self, *_):
            pass

        def reply(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            now = time.time()
            kind, node = peer_identity(self.connection, identity)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                known = node in policy["nodes"] or (identity is not None and node in identity.nodes)
                if kind is None or not known or not 0 < length <= LIMIT:
                    raise Refused("unauthenticated_or_oversized")
                body = json.loads(self.rfile.read(length))
                if self.path == "/v1/begin":
                    self.reply(200, {"lease": state.begin(node, now)})
                elif self.path == "/v1/identity":
                    if identity is None or not state.holds(node, body.get("lease"), now):
                        raise Refused("no_lease")
                    pem = check_identity(identity, node, body["current"], body["csr"], leaf_days=cfg.get("leaf_days", 90))
                    cert = x509.load_pem_x509_certificate(pem.encode())
                    state.record(node, common_name(cert), cert.fingerprint(hashes.SHA256()).hex(), now)
                    self.reply(200, {"certificate": pem})
                elif self.path == "/v1/renew":
                    if kind != "physical":
                        raise Refused("physical_identity_required")
                    if not state.holds(node, body.get("lease"), now):
                        raise Refused("no_lease")
                    pem = check_and_issue(authority, policy, node, body["current"], body["csr"], leaf_days=cfg.get("leaf_days", 90))
                    cert = x509.load_pem_x509_certificate(pem.encode())
                    state.record(node, common_name(cert), cert.fingerprint(hashes.SHA256()).hex(), now)
                    self.reply(200, {"certificate": pem})
                elif self.path == "/v1/done":
                    if body.get("result") not in ("ok", "aborted", "failed"):
                        raise Refused("invalid_result")
                    state.done(node, body.get("lease"), body["result"], now)
                    self.reply(200, {"ok": True})
                else:
                    self.reply(404, {"error": "not_found"})
            except Refused as e:
                print(json.dumps({"issuer": "refused", "node": node, "reason": str(e)}), flush=True)
                self.reply(409, {"error": str(e)})
            except (ValueError, KeyError, TypeError):
                self.reply(400, {"error": "bad_request"})

    # The server leaf is itself renewed in place, and the pki role is not in
    # the renewal restart order: reload it before each accept when it changes.
    # A failed reload (key and certificate briefly out of step) keeps the old
    # chain and retries on the next connection.
    loaded = [cert_stamp(cfg["server_cert"], cfg["server_key"])]

    class Server(http.server.ThreadingHTTPServer):
        def get_request(self):
            stamp = cert_stamp(cfg["server_cert"], cfg["server_key"])
            if stamp != loaded[0]:
                try:
                    ctx.load_cert_chain(cfg["server_cert"], cfg["server_key"])
                    loaded[0] = stamp
                    print(json.dumps({"issuer": "server_certificate_reloaded"}), flush=True)
                except (OSError, ssl.SSLError):
                    pass
            return super().get_request()

    host, port = cfg["listen"].rsplit(":", 1)
    server = Server((host, int(port)), Handler)
    server.daemon_threads = True
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def cert_stamp(*paths):
    out = []
    for p in paths:
        try:
            st = os.stat(p)
            out.append((st.st_ino, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append(None)
    return tuple(out)


def serve_issuer(cfg):
    server = make_issuer(cfg)
    print(json.dumps({"issuer": "listening", "listen": cfg["listen"]}), flush=True)
    server.serve_forever()


# ---------------------------------------------------------------------- agent


class Agent:
    def __init__(self, cfg, client=None, cluster=None, now=utcnow, sleep=time.sleep):
        self.cfg, self.now, self.sleep = cfg, now, sleep
        self.state_dir = Path(cfg["state_dir"])
        self.client = client or self.https
        self.cluster = cluster or self.patroni_cluster

    def log(self, **fields):
        print(json.dumps({"agent": self.cfg["node"], **fields}), flush=True)

    def context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(self.cfg["issuer_ca"])
        ctx.load_cert_chain(self.cfg["client_cert"], self.cfg["client_key"])
        return ctx

    def https(self, path, body):
        host, port = self.cfg["issuer"].rsplit(":", 1)
        conn = http.client.HTTPSConnection(host, int(port), context=self.context(), timeout=30)
        try:
            raw = json.dumps(body).encode()
            conn.request("POST", path, raw, {"Content-Type": "application/json"})
            r = conn.getresponse()
            data = json.loads(r.read(LIMIT))
            if r.status != 200:
                raise Refused(data.get("error", "issuer_error"))
            return data
        finally:
            conn.close()

    def patroni_cluster(self):
        ctx = self.context()
        ctx.load_verify_locations(self.cfg["rest_ca"])
        ctx.check_hostname = False
        conn = http.client.HTTPSConnection(self.cfg["service_ip"], 8008, context=ctx, timeout=15)
        try:
            conn.request("GET", "/cluster")
            return json.loads(conn.getresponse().read(LIMIT))["members"]
        finally:
            conn.close()

    def healthy(self):
        if not self.cfg.get("leaves"):
            return True  # application-only node: no local database cluster
        try:
            members = self.cluster()
        except (OSError, ValueError, KeyError, ssl.SSLError, http.client.HTTPException):
            return False
        leaders = [m for m in members if m.get("role") == "leader" and m.get("state") == "running"]
        replicas = [m for m in members if m.get("role") != "leader"]
        return len(members) == 3 and len(leaders) == 1 and all(m.get("state") == "streaming" and m.get("lag") == 0 for m in replicas)

    def leaves(self):
        out = []
        for leaf in self.cfg.get("leaves", []):
            if "pem" in leaf:
                raw = read_private(leaf["pem"])
                out.append((leaf, pem_certs(raw)[0]))
            else:
                out.append((leaf, x509.load_pem_x509_certificate(read_private(leaf["cert"]))))
        return out

    def identity(self):
        spec = self.cfg.get("identity")
        return None if spec is None else x509.load_pem_x509_certificate(read_private(spec["cert"]))

    def days_left(self, which="all"):
        now = self.now()
        certs = []
        if which in ("all", "physical"):
            certs += [c for _, c in self.leaves()]
        if which in ("all", "identity") and self.cfg.get("identity"):
            certs.append(self.identity())
        if not certs:
            return float("inf")
        return min((expiry(c) - now).total_seconds() / 86400 for c in certs)

    def trust(self):
        cas = []
        for bundle in self.cfg["trust_bundles"]:
            cas.extend(pem_certs(read_private(bundle)))
        return cas

    def handshake(self, name):
        try:
            return json.loads(read_private(self.state_dir / name))
        except FileNotFoundError:
            return None

    def wait_restart(self, generation, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            done = self.handshake("restart-done.json")
            if done and done.get("generation") == generation:
                return done.get("result") == "ok"
            self.sleep(10)
        return False

    def renew(self):
        """One renewal cycle. Returns a status string."""
        request, done = self.handshake("restart-request.json"), self.handshake("restart-done.json")
        recovered = self.recover_commit(request)
        if recovered is not None:
            return recovered
        if request and (not done or done.get("generation") != request["generation"]):
            # Resume after an agent restart: files are committed; await restart.
            ok = self.wait_restart(request["generation"], self.cfg.get("restart_timeout", 7200))
            self.client("/v1/done", {"lease": request["lease"], "result": "ok" if ok else "failed"})
            return "resumed_" + ("ok" if ok else "failed")
        threshold = self.cfg.get("renew_before_days", 30)
        physical = self.days_left("physical") <= threshold
        identity = self.days_left("identity") <= threshold
        if not physical and not identity:
            return "fresh"
        if not self.healthy():
            return "cluster_not_healthy"
        self.backup_paths()  # reject an unusable backup layout before taking the lease
        lease = self.client("/v1/begin", {})["lease"]
        try:
            staged = (self.issue_all(lease) if physical else []) + (self.issue_identity(lease) if identity else [])
        except Exception:
            self.client("/v1/done", {"lease": lease, "result": "aborted"})
            raise
        generation = int(time.time())
        roles = (["physical"] if physical else []) + (["app"] if identity else [])
        request = json.dumps({"generation": generation, "lease": lease, "roles": roles, "requested_at": self.now().isoformat()}).encode()
        marker = self.state_dir / MARKER
        try:
            originals = self.backup(generation)
            # The supervisor defers consumer starts while this marker exists, so
            # nothing starts against a half-written PEM. It is removed only once
            # the files are known to be consistent (committed or restored).
            atomic_write(marker, json.dumps({"generation": generation, "lease": lease}).encode())
            try:
                self.commit(staged)
                atomic_write(self.state_dir / "restart-request.json", request)
            except Exception:
                # Never leave a mix of old and new files, or committed files
                # that no restart will ever load: put the originals back.
                if self.restore(originals):
                    marker.unlink(missing_ok=True)
                raise
            marker.unlink(missing_ok=True)
        except Exception:
            self.client("/v1/done", {"lease": lease, "result": "failed"})
            raise
        self.log(event="committed", generation=generation, files=len(staged))
        ok = self.wait_restart(generation, self.cfg.get("restart_timeout", 7200))
        self.client("/v1/done", {"lease": lease, "result": "ok" if ok else "failed"})
        return "renewed" if ok else "restart_failed"

    def issue_all(self, lease):
        trust = self.trust()
        staged, by_name = [], {}
        for leaf, current in self.leaves():
            key = ec.generate_private_key(ec.SECP256R1())
            csr = x509.CertificateSigningRequestBuilder().subject_name(current.subject).sign(key, hashes.SHA256())
            pem = self.client("/v1/renew", {"lease": lease, "current": current.public_bytes(serialization.Encoding.PEM).decode(), "csr": csr.public_bytes(serialization.Encoding.PEM).decode()})["certificate"]
            new = x509.load_pem_x509_certificate(pem.encode())
            if (
                new.subject != current.subject
                or new.issuer != current.issuer
                or sans(new) != sans(current)
                or eku(new) != eku(current)
                or spki(new.public_key()) != spki(key.public_key())
                or expiry(new) <= expiry(current)
                or not any(signed_by(new, ca) for ca in trust)
            ):
                raise Refused("issued_certificate_failed_verification")
            keypem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            certpem = pem.encode()
            by_name[leaf["name"]] = (certpem, keypem)
            if "pem" in leaf:
                staged.append((leaf["pem"], certpem + keypem))
            else:
                staged += [(leaf["cert"], certpem), (leaf["key"], keypem)]
        for copy in self.cfg.get("copies", []):
            certpem, keypem = by_name[copy["from"]]
            staged += [(copy["cert"], certpem), (copy["key"], keypem)]
        return staged

    def issue_identity(self, lease):
        spec = self.cfg["identity"]
        current = self.identity()
        key = serialization.load_pem_private_key(read_private(spec["key"]), None)
        algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        csr = x509.CertificateSigningRequestBuilder().subject_name(current.subject).sign(key, algorithm)
        pem = self.client("/v1/identity", {"lease": lease, "current": current.public_bytes(serialization.Encoding.PEM).decode(), "csr": csr.public_bytes(serialization.Encoding.PEM).decode()})["certificate"]
        new = x509.load_pem_x509_certificate(pem.encode())
        cas = pem_certs(read_private(spec["ca"]))
        if (
            new.subject != current.subject
            or new.issuer != current.issuer
            or sans(new) != sans(current)
            or uris(new) != uris(current)
            or spki(new.public_key()) != spki(current.public_key())
            or expiry(new) <= expiry(current)
            or not any(signed_by(new, ca) for ca in cas)
        ):
            raise Refused("issued_identity_failed_verification")
        return [(spec["cert"], pem.encode())]

    def backup_paths(self):
        """Map each managed file to its flattened backup name; names must not collide."""
        paths = [p for leaf in self.cfg.get("leaves", []) for p in ([leaf["pem"]] if "pem" in leaf else [leaf["cert"], leaf["key"]])]
        if self.cfg.get("identity"):
            paths.append(self.cfg["identity"]["cert"])
        paths += [p for c in self.cfg.get("copies", []) for p in (c["cert"], c["key"])]
        names = {}
        for path in dict.fromkeys(paths):
            name = re.sub(r"[^A-Za-z0-9._-]", "_", path.strip("/"))
            if name in names.values():
                raise Refused("backup_name_collision")
            names[path] = name
        return names

    def backup(self, generation):
        """Copy every managed file under the state directory; return the originals."""
        target = self.state_dir / ("backup-%d" % generation)
        target.mkdir(mode=0o700)
        originals = {}
        for path, name in self.backup_paths().items():
            originals[path] = read_private(path)
            atomic_write(target / name, originals[path])
        return originals

    def recover_commit(self, request):
        """Settle a commit marker left by a crash or an incomplete restore.

        Returns None when there is nothing to recover (or the commit had
        completed), otherwise a cycle status. Consumers stay blocked until the
        managed files are back to the backed-up originals.
        """
        marker = self.state_dir / MARKER
        try:
            state = json.loads(read_private(marker))
        except FileNotFoundError:
            return None
        generation = state["generation"]
        if request and request.get("generation") == generation:
            marker.unlink(missing_ok=True)  # commit and restart request completed
            return None
        target = self.state_dir / ("backup-%d" % generation)
        try:
            originals = {path: read_private(target / name) for path, name in self.backup_paths().items()}
        except (OSError, Refused):
            self.log(event="commit_recovery_blocked", generation=generation, reason="backup_unreadable")
            return "commit_recovery_blocked"
        if not self.restore(originals):
            return "commit_recovery_blocked"
        marker.unlink(missing_ok=True)
        if state.get("lease"):
            try:  # may already be reported or expired; the files are what matter
                self.client("/v1/done", {"lease": state["lease"], "result": "failed"})
            except Exception as e:
                self.log(event="commit_recovery_lease_report_failed", reason=type(e).__name__)
        self.log(event="commit_recovered", generation=generation)
        return "commit_recovered"

    def restore(self, originals):
        failed = []
        for path, body in originals.items():
            try:
                if read_private(path) != body:
                    rewrite_in_place(path, body)
            except Exception:  # keep restoring the rest; report every miss
                failed.append(path)
        if failed:
            self.log(event="restore_incomplete", files=failed)
            return False
        self.log(event="restored")
        return True

    def commit(self, staged):
        # Keys before certificates: a reader that races sees the old cert with
        # a new key only until the cert lands; processes reload on restart.
        for path, body in sorted(staged, key=lambda item: not item[0].endswith(".key")):
            if os.path.exists(path) and read_private(path) == body:
                continue
            rewrite_in_place(path, body)

    def run(self):
        interval = self.cfg.get("check_interval_seconds", 3600)
        retry = min(interval, self.cfg.get("recovery_retry_seconds", 60))
        while True:
            try:
                self.log(event="cycle", status=self.renew(), days_left=round(self.days_left(), 1))
            except Exception as e:  # keep the agent alive; report a static reason
                self.log(event="cycle", status="error", reason=type(e).__name__, detail=str(e)[:200])
            # A surviving marker means a commit is unsettled: retry soon, since
            # leaf consumers stay stopped until it is recovered.
            self.sleep(retry if (self.state_dir / MARKER).exists() else interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "check"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    cfg = load_json(args.config)
    if args.mode == "check":
        print(json.dumps({"node": cfg["agent"]["node"], "days_left": round(Agent(cfg["agent"]).days_left(), 1)}))
        return 0
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        # Leaves are owned by their consuming UIDs (etcd, Patroni, router) and
        # the supervisor accepts only root-owned handshakes, so the agent runs
        # as UID 0 with every capability dropped except CAP_DAC_OVERRIDE.
        print("pki role must run as UID 0 (cap_drop ALL, cap_add DAC_OVERRIDE)", file=sys.stderr)
        return 2
    if "issuer" in cfg:  # only the CA master carries an issuer section
        threading.Thread(target=serve_issuer, args=(cfg["issuer"],), daemon=True).start()
    Agent(cfg["agent"]).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
