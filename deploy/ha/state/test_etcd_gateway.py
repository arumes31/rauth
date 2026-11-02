#!/usr/bin/env python3
"""Real etcd TLS regression on a disposable Docker network; not an HA proof."""

import base64
import ipaddress
import json
import os
from pathlib import Path
import ssl
import http.client
import subprocess
import tempfile
import time
import uuid

import render

IMAGE = "gcr.io/etcd-development/etcd:v3.7.3@sha256:0d27b9478551f431f82d1e0ddb6c87ad07ebae8b904c637f3a99213349523910"


def run(*args):
    try:
        return subprocess.check_output(
            list(args), stderr=subprocess.STDOUT, text=True, timeout=120
        ).strip()
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            "Fixture command failed: "
            + " ".join(args)
            + ": "
            + (error.output or "")[-1500:]
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Fixture command timed out: " + " ".join(args)) from error
    except OSError as error:
        raise RuntimeError("Fixture command unavailable: " + " ".join(args)) from error


def unused_subnet():
    # Do not depend on unused Docker default-pool capacity on a busy test host.
    # Never override a host route or another Docker network's address space.
    occupied = []
    for route in json.loads(run("ip", "-json", "route", "show", "table", "all")):
        destination = route.get("dst")
        if destination and destination not in ("default", "0.0.0.0/0"):
            net = ipaddress.ip_network(destination, strict=False)
            if net.version == 4:
                occupied.append(net)
    ids = run("docker", "network", "ls", "-q").splitlines()
    if ids:
        for network in json.loads(run("docker", "network", "inspect", *ids)):
            for config in network.get("IPAM", {}).get("Config") or []:
                if config.get("Subnet"):
                    net = ipaddress.ip_network(config["Subnet"])
                    if net.version == 4:
                        occupied.append(net)
    offset = uuid.uuid4().int % 256
    for i in range(256):
        candidate = ipaddress.ip_network(f"10.254.{(offset + i) % 256}.0/28")
        if not any(candidate.overlaps(net) for net in occupied):
            return candidate
    raise RuntimeError("No verified non-overlapping test subnet is available")


def ca(root, name):
    key, cert = root / (name + ".key"), root / (name + ".crt")
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=" + name,
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    key.chmod(0o600)
    return cert, key


def leaf(root, name, issuer, usage, ip):
    key, cert, csr, ext = (
        root / (name + suffix) for suffix in (".key", ".crt", ".csr", ".ext")
    )
    run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        "/CN=" + name,
        "-keyout",
        str(key),
        "-out",
        str(csr),
    )
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=" + usage + "\nsubjectAltName=IP:" + ip + "\n"
    )
    run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(issuer[0]),
        "-CAkey",
        str(issuer[1]),
        "-set_serial",
        str(uuid.uuid4().int),
        "-days",
        "1",
        "-extfile",
        str(ext),
        "-out",
        str(cert),
    )
    key.chmod(0o600)
    return cert, key


def main():
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError(
            "Run the disposable Docker integration test on Linux as root"
        )
    name = "rauth-etcd-tls-" + uuid.uuid4().hex[:12]
    network = None
    container = None
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix=name + "-") as directory:
        root = Path(directory)
        try:
            run("docker", "pull", IMAGE)
            available = unused_subnet()
            network = run(
                "docker",
                "network",
                "create",
                "--subnet",
                str(available),
                "--label",
                "io.rauth.test=" + name,
                name,
            )
            net = json.loads(run("docker", "network", "inspect", network))[0]
            subnet = ipaddress.ip_network(net["IPAM"]["Config"][0]["Subnet"])
            ip = str(subnet.network_address + 2)
            authorities = root / "authority"
            authorities.mkdir()
            server_ca, client_ca, peer_ca = (
                ca(authorities, n) for n in ("server", "client", "peer")
            )
            pki, data = root / "pki", root / "data"
            pki.mkdir()
            data.mkdir()
            for n, authority, usage in (
                ("server", server_ca, "serverAuth"),
                ("loopback", client_ca, "clientAuth"),
                ("peer", peer_ca, "serverAuth,clientAuth"),
            ):
                leaf(pki, n, authority, usage, ip)
            (pki / "client-ca.crt").write_bytes(
                client_ca[0].read_bytes() + server_ca[0].read_bytes()
            )
            (pki / "peer-ca.crt").write_bytes(peer_ca[0].read_bytes())
            operator = leaf(root, "operator", client_ca, "clientAuth", ip)
            for path in [data, pki, *pki.iterdir()]:
                os.chown(path, 10003, 10003)
                path.chmod(0o700 if path.is_dir() else 0o600)
            # Use the rendered command with only the topology reduced to one
            # member for this certificate regression. Full HA is tested elsewhere.
            manifest = json.loads(
                Path(__file__).with_name("manifest.example.json").read_text()
            )
            state = manifest["nodes"][0]
            spec = json.loads(
                render.render(manifest, state["name"])["compose.state.json"]
            )["services"]["etcd"]
            args = [
                "--initial-cluster=" + state["name"] + "=https://" + ip + ":2380"
                if x.startswith("--initial-cluster=")
                else x.replace(state["ip"], ip)
                for x in spec["command"]
            ]
            meta = json.loads(run("docker", "image", "inspect", IMAGE))[0]
            if not set(meta["Config"].get("Volumes") or {}) <= {
                "/var/lib/etcd",
                "/etc/etcd",
            }:
                raise AssertionError("Uncovered image VOLUME")
            container = run(
                "docker",
                "create",
                "--name",
                name,
                "--label",
                "io.rauth.test=" + name,
                "--network",
                network,
                "--ip",
                ip,
                "--user",
                "10003:10003",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "128m",
                "--memory-swap",
                "128m",
                "--pids-limit",
                "128",
                "--mount",
                "type=bind,src=" + str(data) + ",dst=/var/lib/etcd",
                "--mount",
                "type=bind,src=" + str(pki) + ",dst=/etc/etcd,readonly",
                "--entrypoint",
                spec["entrypoint"][0],
                IMAGE,
                *args,
            )

            run("docker", "start", container)

            def context(identity=None):
                ctx = ssl.create_default_context(cafile=str(server_ca[0]))
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                if identity:
                    ctx.load_cert_chain(str(identity[0]), str(identity[1]))
                return ctx

            def request(ctx, path, payload=None):
                connection = http.client.HTTPSConnection(
                    ip, 2379, context=ctx, timeout=2
                )
                try:
                    connection.request(
                        "GET" if payload is None else "POST",
                        path,
                        body=None if payload is None else json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    response = connection.getresponse()
                    body = response.read(65537)
                    if response.status != 200 or len(body) > 65536:
                        raise AssertionError(
                            "Unexpected etcd API response: " + str(response.status)
                        )
                    return json.loads(body)
                finally:
                    connection.close()

            ctx = context(operator)
            deadline = time.monotonic() + 20
            while True:
                try:
                    if request(ctx, "/health")["health"] not in (True, "true"):
                        raise AssertionError("Unhealthy")
                    break
                except (OSError, AssertionError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
            key, value = (
                base64.b64encode(x.encode()).decode() for x in ("/regression", name)
            )
            request(ctx, "/v3/kv/put", {"key": key, "value": value})
            if request(ctx, "/v3/kv/range", {"key": key})["kvs"][0]["value"] != value:
                raise AssertionError("Gateway did not persist the marker")
            for identity in (
                None,
                (pki / "server.crt", pki / "server.key"),
                (pki / "peer.crt", pki / "peer.key"),
            ):
                try:
                    request(context(identity), "/health")
                except (ssl.SSLError, ConnectionError):
                    pass
                else:
                    raise AssertionError(
                        "Missing, wrong-purpose or untrusted client was accepted"
                    )
                # A transport failure is not evidence of authorization rejection
                # unless an authenticated request still succeeds immediately.
                request(ctx, "/health")
            state = json.loads(run("docker", "inspect", container))[0]
            if (
                not state["State"]["Running"]
                or state["State"]["OOMKilled"]
                or any(m["Type"] != "bind" for m in state["Mounts"])
            ):
                raise AssertionError("Unexpected fixture resource or storage state")
            print(
                json.dumps(
                    {
                        "gateway_health": True,
                        "durable_marker": True,
                        "client_cert_required": True,
                        "server_only_and_peer_cert_rejected": True,
                        "ha_test": False,
                    }
                )
            )
        finally:
            if container:
                state = json.loads(run("docker", "inspect", container))[0]
                if state["Config"]["Labels"].get("io.rauth.test") != name:
                    raise RuntimeError("Refusing to remove an unrelated container")
                run("docker", "rm", "-f", container)
            if network:
                net = json.loads(run("docker", "network", "inspect", network))[0]
                if net["Labels"].get("io.rauth.test") != name:
                    raise RuntimeError("Refusing to remove an unrelated network")
                run("docker", "network", "rm", network)


if __name__ == "__main__":
    main()
