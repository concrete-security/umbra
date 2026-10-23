"""Real Security CVM wire journeys, without a provider or internet services.

The production mitmdump addon, polling/emission loops, CA management listener,
and upgrade tunnel run in child processes. Only the Console and destination are
fixtures. Both use verified TLS; this does not exercise TEE attestation, Shade,
or the Dev CVM's Sysbox/network boundary.

Install the locked ``mitmproxy`` extra to run. ``UMBRA_E2E_REQUIRED=1`` makes a
missing extra an error instead of an optional-suite skip.

``UMBRA_TEST_SECURITY_IMAGE=repository@sha256:...`` runs the same journeys
against installed entrypoints in the immutable release image on Docker.
Security CVM containers never receive source mounts, and the image is never
rebuilt. A separate unprivileged fixture container receives the test server
module and synthetic TLS material. All traffic stays on owned runner bridges
and loopback listeners; no provider, external service, or attestation is used.
"""

from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
from threading import Lock, Thread
import time
from typing import Callable, Iterator
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx
import pytest

from egress_fixture_server import State as ContainerFixtureState
from umbra_security_cvm.ca import generate_root_ca
from umbra_security_cvm.mitmproxy_runtime import MITMPROXY_SCRIPT_ENV, mitmdump_args


CVM_ID = "00000000-0000-4000-8000-000000000010"
PROXY_TOKEN = "e2e-proxy-bearer"
INGEST_TOKEN = "e2e-ingest-bearer"
EXPORT_TOKEN = "e2e-export-bearer"
INJECTED_VALUE = "e2e-injected-credential"
DLP_VALUE = "E2E_DLP_SENTINEL_ABC123"
QUERY_VALUE = "e2e-query-must-not-be-logged"
RESPONSE_BODY = b'{"ok":true}'
TIMEOUT_SECONDS = 10


def eventually(predicate: Callable[[], bool], *, message: str) -> None:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    pytest.fail(message)


def unused_ports(count: int) -> list[int]:
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket()) for _ in range(count)]
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]


def fixture_tls(directory: Path, host: str = "127.0.0.1") -> tuple[ssl.SSLContext, Path]:
    """Issue localhost certificates so neither TLS hop needs insecure mode."""
    ca = generate_root_ca(common_name="Umbra e2e fixture root")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    try:
        host_name = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        host_name = x509.DNSName(host)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), host_name]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca.private_key, hashes.SHA384())
    )
    ca_path = directory / "fixture-ca.pem"
    ca_path.write_bytes(ca.ca_pem)
    ca_path.chmod(0o644)
    cert_path = directory / "fixture-cert.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path = directory / "fixture-key.pem"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return context, ca_path


@contextmanager
def serve_http(handler: type[BaseHTTPRequestHandler], tls: ssl.SSLContext | None = None,
               *, host: str = "127.0.0.1") -> Iterator[int]:
    server = ThreadingHTTPServer((host, 0), handler)
    server.daemon_threads = True
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def respond(self, status: int, body: bytes = b"", *, etag: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if etag is not None:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)


class ConsoleFixture:
    def __init__(self) -> None:
        self.lock = Lock()
        self.entries: list[dict[str, object]] = []
        self.version = 0
        self.applied_etag: str | None = None
        self.outage = False
        self.failed_polls = 0
        self.logs: list[dict[str, object]] = []
        self.ingested_batches: set[str] = set()
        self.rejected_auth = 0

    def replace(self, entries: list[dict[str, object]]) -> None:
        with self.lock:
            self.version += 1
            self.entries = entries
            self.applied_etag = None
            expected = f'"e2e-{self.version}"'
        # A subsequent conditional GET carrying this ETag proves that the real
        # polling loop has parsed and installed the preceding snapshot.
        eventually(lambda: self.applied_etag == expected, message="Security CVM did not install the control snapshot")

    def handler(self) -> type[QuietHandler]:
        fixture = self

        class Handler(QuietHandler):
            def authenticated(self) -> bool:
                if self.headers.get("Authorization") == f"Bearer {INGEST_TOKEN}":
                    return True
                with fixture.lock:
                    fixture.rejected_auth += 1
                self.respond(401)
                return False

            def do_GET(self) -> None:
                if not self.authenticated():
                    return
                if self.path != "/internal/sc-control/cvms":
                    self.respond(404)
                    return
                with fixture.lock:
                    if fixture.outage:
                        fixture.failed_polls += 1
                        status, body, etag = 503, b"", None
                    else:
                        etag = f'"e2e-{fixture.version}"'
                        if self.headers.get("If-None-Match") == etag:
                            fixture.applied_etag = etag
                            status, body = 304, b""
                        else:
                            status, body = 200, json.dumps({"entries": fixture.entries}).encode()
                self.respond(status, body, etag=etag)

            def do_POST(self) -> None:
                if not self.authenticated():
                    return
                if self.path != "/internal/traffic-logs":
                    self.respond(404)
                    return
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with fixture.lock:
                    if payload["idempotency_key"] not in fixture.ingested_batches:
                        fixture.logs.extend(payload["logs"])
                        fixture.ingested_batches.add(payload["idempotency_key"])
                self.respond(200, b'{"accepted":true}')

        return Handler


class OriginFixture:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.lock = Lock()

    def handler(self) -> type[QuietHandler]:
        fixture = self

        class Handler(QuietHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with fixture.lock:
                    fixture.requests.append({
                        "path": self.path,
                        "headers": {name.lower(): value for name, value in self.headers.items()},
                        "body": body,
                    })
                self.respond(200, RESPONSE_BODY)

        return Handler


def release_image_reference() -> str | None:
    image = os.environ.get("UMBRA_TEST_SECURITY_IMAGE")
    if image is None:
        return None
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image):
        raise ValueError("UMBRA_TEST_SECURITY_IMAGE must be an immutable runtime image reference")
    return image


class RemoteFixtures:
    def __init__(self, port: int, token: str) -> None:
        self.url = f"http://127.0.0.1:{port}"
        self.token = token

    def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        with httpx.Client(trust_env=False, timeout=5) as client:
            response = client.request(method, self.url + path, json=payload,
                                      headers={"Authorization": "Bearer " + self.token})
        response.raise_for_status()
        return response.json()

    def state(self) -> dict:
        return self.call("GET", "/state")

    def ready(self) -> bool:
        try:
            return self.state()["version"] == 0
        except (httpx.HTTPError, ValueError, KeyError):
            return False


class RemoteConsoleFixture:
    def __init__(self, fixtures: RemoteFixtures) -> None:
        self.fixtures = fixtures
        self.lock = Lock()

    @property
    def version(self) -> int:
        return self.fixtures.state()["version"]

    @property
    def logs(self) -> list[dict]:
        return self.fixtures.state()["logs"]

    @property
    def rejected_auth(self) -> int:
        return self.fixtures.state()["rejected_auth"]

    @property
    def failed_polls(self) -> int:
        return self.fixtures.state()["failed_polls"]

    @property
    def outage(self) -> bool:
        return self.fixtures.state()["outage"]

    @outage.setter
    def outage(self, value: bool) -> None:
        self.fixtures.call("POST", "/control", {"outage": value})

    def replace(self, entries: list[dict[str, object]]) -> None:
        version = self.fixtures.call("POST", "/control", {"entries": entries})["version"]
        expected = f'"e2e-{version}"'
        eventually(lambda: self.fixtures.state()["applied_etag"] == expected,
                   message="Security CVM did not install the control snapshot")


class RemoteOriginFixture:
    def __init__(self, fixtures: RemoteFixtures) -> None:
        self.fixtures = fixtures

    @property
    def requests(self) -> list[dict]:
        return [{"path": request["path"], "headers": request["headers"],
                 "body": base64.b64decode(request["body_base64"])}
                for request in self.fixtures.state()["requests"]]


class ImageRuntime:
    """Keep release containers and the fixture-only network owned by this test."""

    def __init__(self, image: str, directory: Path, stack: ExitStack) -> None:
        self.image = image
        self.directory = directory
        self.names: list[str] = []
        self.processes: list[subprocess.Popen[bytes]] = []
        self.network = "umbra-sc-e2e-" + uuid.uuid4().hex
        self.ingress_network = self.network + "-ingress"
        self.docker(["image", "inspect", image])
        self.docker(["network", "create", "--internal", self.network])
        stack.callback(self.cleanup)
        # Docker omits published ports for internal-only containers. Keep a
        # separate owned ingress bridge for loopback-published test listeners.
        self.docker(["network", "create", self.ingress_network])
        self.host = self.network + "-fixtures.test"

    @staticmethod
    def docker(args: list[str]) -> str:
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            # Daemon output can include environment material; report only action.
            raise RuntimeError(f"release-image Docker {args[0]} operation failed")
        return result.stdout

    def command(self, name: str, env: dict[str, str], ports: list[tuple[int, int]],
                mounts: list[tuple[Path, str]], executable: str, extra_args: list[str] | None = None) -> list[str]:
        container = self.network + "-" + name
        env_path = self.directory / f"{name}.env"
        env_path.touch(mode=0o600, exist_ok=False)
        env_path.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        self.names.append(container)
        network = f"name={self.network},alias={self.host}" if name == "fixtures" else self.network
        args = [
            "docker", "run", "--rm", "--pull=never", "--name", container,
            "--platform", "linux/amd64", "--network", network,
            "--network", self.ingress_network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp",
            "--tmpfs", "/run", "--env-file", str(env_path),
        ]
        if name == "mitmproxy":
            args.extend(["--tmpfs", "/tmp/mitmproxy:uid=10001,gid=10001,mode=0700"])
        for outside, inside in ports:
            args.extend(["--publish", f"127.0.0.1:{outside}:{inside}"])
        for source, target in mounts:
            args.extend(["--mount", f"type=bind,src={source},dst={target},readonly"])
        return [*args, self.image, executable, *(extra_args or [])]

    def assert_running(self) -> None:
        for name in self.names:
            details = json.loads(self.docker(["container", "inspect", name]))[0]
            if details["State"]["Running"] is not True:
                raise RuntimeError("release Security CVM container stopped unexpectedly")

    def published_port(self, name: str, port: int) -> int:
        selected = []

        def assigned() -> bool:
            try:
                details = json.loads(self.docker(["container", "inspect", self.network + "-" + name]))[0]
            except RuntimeError:
                return False
            bindings = (details["NetworkSettings"].get("Ports") or {}).get(f"{port}/tcp")
            if bindings:
                selected.append(int(bindings[0]["HostPort"]))
                return True
            return False

        eventually(assigned, message="Docker did not assign the loopback fixture listener")
        return selected[0]

    def cleanup(self) -> None:
        failures = []
        for name in reversed(self.names):
            try:
                self.docker(["container", "rm", "--force", name])
            except (RuntimeError, subprocess.SubprocessError):
                failures.append("container")
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                failures.append("process")
        for network in (self.ingress_network, self.network):
            try:
                self.docker(["network", "rm", network])
            except (RuntimeError, subprocess.SubprocessError):
                failures.append("network")
        if failures:
            raise RuntimeError("release-image cleanup failed: " + ", ".join(failures))


class EgressHarness:
    def __init__(self, directory: Path, stack: ExitStack) -> None:
        self.directory = directory
        self.stack = stack
        self.processes: list[subprocess.Popen[bytes]] = []
        self.log_paths: list[Path] = []
        self.fixture_token = ""
        self.fixture_control: RemoteFixtures | None = None
        self.untrusted_port: int | None = None
        image = release_image_reference()
        self.image_runtime = ImageRuntime(image, directory, stack) if image else None
        self.destination_host = self.image_runtime.host if self.image_runtime else "127.0.0.1"
        tls, ca_path = fixture_tls(directory, self.destination_host)
        if self.image_runtime:
            untrusted_directory = directory / "untrusted-fixture"
            untrusted_directory.mkdir()
            fixture_tls(untrusted_directory, self.destination_host)
            # These keys belong only to the disposable test issuers. Copies are
            # readable by the fixture container's unprivileged UID, while the
            # original host keys retain mode 0600 and never enter SC containers.
            mounts = []
            for issuer, issuer_directory in (("trusted", directory), ("untrusted", untrusted_directory)):
                for part in ("cert", "key"):
                    source = directory / f"fixture-server-{issuer}-{part}.pem"
                    source.write_bytes((issuer_directory / f"fixture-{part}.pem").read_bytes())
                    source.chmod(0o644)
                    mounts.append((source, f"/umbra-fixtures/{issuer}-{part}.pem"))
            config_path = directory / "fixture-server.json"
            config_path.write_text(json.dumps({
                "ingest_token": INGEST_TOKEN,
                **{f"{issuer}_{part}": f"/umbra-fixtures/{issuer}-{part}.pem"
                   for issuer in ("trusted", "untrusted") for part in ("cert", "key")},
            }))
            config_path.chmod(0o644)
            mounts.extend([
                (config_path, "/umbra-fixtures/config.json"),
                (Path(__file__).with_name("egress_fixture_server.py"), "/umbra-fixtures/server.py"),
            ])
            self.fixture_token = secrets.token_urlsafe(32)
            self.start("fixtures", self.image_runtime.command(
                "fixtures", {"UMBRA_FIXTURE_CONTROL_TOKEN": self.fixture_token}, [(0, 8089)],
                mounts, "python", ["/umbra-fixtures/server.py", "/umbra-fixtures/config.json"],
            ), dict(os.environ))
            control_port = self.image_runtime.published_port("fixtures", 8089)
            self.wait_listener(control_port)
            self.fixture_control = RemoteFixtures(control_port, self.fixture_token)
            eventually(self.fixture_control.ready, message="Container-local test fixtures did not become ready")
            self.console = RemoteConsoleFixture(self.fixture_control)
            self.origin = RemoteOriginFixture(self.fixture_control)
            self.http_port, self.https_port, self.blocked_port, self.untrusted_port, console_port = 8083, 8443, 8444, 8445, 8446
        else:
            self.console = ConsoleFixture()
            self.origin = OriginFixture()
            self.http_port = stack.enter_context(serve_http(self.origin.handler()))
            self.https_port = stack.enter_context(serve_http(self.origin.handler(), tls))
            self.blocked_port = stack.enter_context(serve_http(self.origin.handler(), tls))
            console_port = stack.enter_context(serve_http(self.console.handler(), tls))
        proxy_port, management_port, self.tunnel_port = (8080, 0, 0) if self.image_runtime else unused_ports(3)
        source = Path(__file__).resolve().parents[1] / "src"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(source),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SSL_CERT_FILE": str(ca_path),
            "CONSOLE_URL": f"https://{self.destination_host}:{console_port}",
            "ENTITY_ID": "00000000-0000-4000-8000-000000000001",
            "SC_ID": "00000000-0000-4000-8000-000000000002",
            "CONSOLE_INGEST_TOKEN": INGEST_TOKEN,
            "CA_EXPORT_TOKEN": EXPORT_TOKEN,
            "SC_MANAGEMENT_HOST": "127.0.0.1",
            "SC_MANAGEMENT_PORT": str(management_port),
            "SC_MITMPROXY_HOST": "127.0.0.1",
            "SC_MITMPROXY_PORT": str(proxy_port),
            "SC_MITMPROXY_CONFDIR": str(directory / "mitmproxy"),
            "SC_CONTROL_INTERVAL_SECONDS": "0.05",
            "SC_CONTROL_JITTER_SECONDS": "0",
            "SC_TRAFFIC_FLUSH_INTERVAL_SECONDS": "0.05",
            MITMPROXY_SCRIPT_ENV: "1",
        }
        tunnel_env = {
            "PATH": env["PATH"],
            "PYTHONPATH": str(source),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SC_PROXY_TUNNEL_HOST": "127.0.0.1",
            "SC_PROXY_TUNNEL_PORT": str(self.tunnel_port),
            "SC_PROXY_TUNNEL_UPSTREAM_HOST": "127.0.0.1",
            "SC_PROXY_TUNNEL_UPSTREAM_PORT": str(proxy_port),
        }
        if self.image_runtime:
            container_ca = "/umbra-fixtures/fixture-ca.pem"
            config_path = directory / "mitmproxy-fixture.yaml"
            config_path.write_text(f"ssl_verify_upstream_trusted_ca: {container_ca}\n")
            config_path.chmod(0o644)
            container_env = {
                key: value for key, value in env.items()
                if key not in {"PATH", "PYTHONPATH", MITMPROXY_SCRIPT_ENV}
            }
            container_env.update({
                "SSL_CERT_FILE": container_ca, "SC_MANAGEMENT_HOST": "0.0.0.0",
                "SC_MITMPROXY_HOST": "0.0.0.0", "SC_MANAGEMENT_PORT": "8081",
                "SC_MITMPROXY_PORT": "8080", "SC_MITMPROXY_CONFDIR": "/tmp/mitmproxy",
            })
            self.start("mitmdump", self.image_runtime.command(
                "mitmproxy", container_env, [(management_port, 8081)],
                [(ca_path, container_ca), (config_path, "/tmp/mitmproxy/config.yaml")],
                "umbra-security-mitmproxy",
            ), dict(os.environ))
            management_port = self.image_runtime.published_port("mitmproxy", 8081)
            tunnel_env = {
                "SC_PROXY_TUNNEL_HOST": "0.0.0.0", "SC_PROXY_TUNNEL_PORT": "8082",
                "SC_PROXY_TUNNEL_UPSTREAM_HOST": self.image_runtime.network + "-mitmproxy",
                "SC_PROXY_TUNNEL_UPSTREAM_PORT": "8080",
            }
            self.start("proxy-tunnel", self.image_runtime.command(
                "proxy-tunnel", tunnel_env, [(self.tunnel_port, 8082)], [],
                "umbra-security-proxy-tunnel",
            ), dict(os.environ))
            self.tunnel_port = self.image_runtime.published_port("proxy-tunnel", 8082)
        else:
            # Keep the production option builder and startup addon. The only
            # extra option trusts the fixture issuer for upstream TLS.
            args = mitmdump_args(env=env)
            self.start(
                "mitmdump",
                [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()", *args[1:],
                 "--set", f"ssl_verify_upstream_trusted_ca={ca_path}"], env,
            )
            self.start("proxy-tunnel", [sys.executable, "-m", "umbra_security_cvm.proxy_tunnel"], tunnel_env)
        self.wait_listener(management_port)
        self.wait_listener(self.tunnel_port)
        self.console.replace(self.entries())
        with httpx.Client(trust_env=False, timeout=5) as client:
            response = client.get(
                f"http://127.0.0.1:{management_port}/ca.pem",
                headers={"Authorization": f"Bearer {EXPORT_TOKEN}"},
            )
        response.raise_for_status()
        assert b"PRIVATE KEY" not in response.content
        self.client_tls = ssl.create_default_context(cadata=response.text)

    def start(self, name: str, args: list[str], env: dict[str, str]) -> None:
        log_path = self.directory / f"{name}.log"
        output = self.stack.enter_context(log_path.open("wb"))
        process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        self.processes.append(process)
        self.log_paths.append(log_path)
        if self.image_runtime:
            self.image_runtime.processes.append(process)
        else:
            self.stack.callback(self.stop, process)

    @staticmethod
    def stop(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def wait_listener(self, port: int) -> None:
        def ready() -> bool:
            if any(process.poll() is not None for process in self.processes):
                pytest.fail("Security CVM subprocess exited before readiness: " + self.sanitized_output())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return True
            except OSError:
                return False
        eventually(ready, message="Security CVM listener did not become ready")

    def sanitized_output(self) -> str:
        output = "\n".join(path.read_text(errors="replace") for path in self.log_paths)
        for value in (PROXY_TOKEN, INGEST_TOKEN, EXPORT_TOKEN, INJECTED_VALUE, DLP_VALUE, QUERY_VALUE,
                      self.fixture_token):
            if not value:
                continue
            output = output.replace(value, "[fixture value redacted]")
        return output[-4000:]

    def policy(self) -> dict[str, object]:
        rules = [
            {"id": f"allow.{scheme}", "scheme": scheme, "host": self.destination_host, "ports": [port],
             "methods": ["POST"], "path_prefixes": ["/allowed"]}
            for scheme, port in (("http", self.http_port), ("https", self.https_port))
        ]
        return {
            "allowed_destinations": rules,
            "blocked_destinations": [
                {"id": "block.destination", "scheme": "https", "host": self.destination_host, "ports": [self.blocked_port],
                 "methods": ["*"], "path_prefixes": ["/"]},
            ],
            "secret_patterns": [
                {"id": "fixture-dlp", "name": "Fixture sentinel", "pattern": DLP_VALUE,
                 "scan_headers": True, "scan_body": True},
            ],
            "secret_injections": [
                {"id": f"inject.{rule['scheme']}", "match": {key: value for key, value in rule.items() if key != "id"},
                 "type": "request_header", "header": "authorization", "value": INJECTED_VALUE,
                 "value_template": "Bearer ${secret}"}
                for rule in rules
            ],
            "sandbox_env": [],
        }

    def entries(self, policy: dict[str, object] | None = None) -> list[dict[str, object]]:
        return [{
            "cvm_id": CVM_ID,
            "fqdn": "e2e.dev.example.invalid",
            "proxy_token_hash": hashlib.sha256(PROXY_TOKEN.encode()).hexdigest(),
            "merged_policy": self.policy() if policy is None else policy,
            "policy_version": self.console.version + 1,
            "updated_at": "2026-10-23T00:00:00Z",
        }]

    @contextmanager
    def tunnel(self) -> Iterator[socket.socket]:
        with socket.create_connection(("127.0.0.1", self.tunnel_port), timeout=5) as connection:
            connection.sendall(
                b"GET /umbra/proxy HTTP/1.1\r\nHost: localhost\r\n"
                b"Connection: Upgrade\r\nUpgrade: umbra-proxy\r\n\r\n"
            )
            assert read_headers(connection).startswith(b"HTTP/1.1 101 ")
            yield connection

    @contextmanager
    def https_connection(self, *, port: int | None = None) -> Iterator[socket.socket]:
        port = self.https_port if port is None else port
        with self.tunnel() as connection:
            connection.sendall(
                (f"CONNECT {self.destination_host}:{port} HTTP/1.1\r\n"
                 f"Host: {self.destination_host}:{port}\r\nProxy-Authorization: Bearer {PROXY_TOKEN}\r\n\r\n").encode()
            )
            assert read_headers(connection).startswith(b"HTTP/1.1 200 ")
            with self.client_tls.wrap_socket(connection, server_hostname=self.destination_host) as secure:
                yield secure

    def request(self, *, scheme: str = "https", body: bytes = b"harmless-body", headers: dict[str, str] | None = None,
                path: str = "/allowed", connection: socket.socket | None = None,
                port: int | None = None) -> tuple[int, dict[str, str], bytes]:
        port = self.https_port if port is None else port
        if connection is not None:
            return send_request(connection, path, body, headers or {}, port=port, host=self.destination_host)
        if scheme == "https":
            with self.https_connection(port=port) as secure:
                return send_request(secure, path, body, headers or {}, port=port, host=self.destination_host)
        with self.tunnel() as plain:
            return send_request(
                plain, f"http://{self.destination_host}:{self.http_port}{path}", body,
                {"Proxy-Authorization": f"Bearer {PROXY_TOKEN}", **(headers or {})}, port=self.http_port,
                host=self.destination_host,
            )

    def wait_log(self, *, path: str, decision: str, status: int) -> dict[str, object]:
        def matching() -> list[dict[str, object]]:
            return [record for record in self.console.logs
                    if record["path"] == path and record["decision"] == decision and record["response_code"] == status]
        eventually(lambda: bool(matching()), message=f"No {decision} traffic record for {path}")
        assert self.console.rejected_auth == 0
        record = matching()[-1]
        assert record["cvm_id"] == CVM_ID
        return record


def read_headers(connection: socket.socket) -> bytes:
    headers = bytearray()
    while not headers.endswith(b"\r\n\r\n"):
        byte = connection.recv(1)
        if not byte:
            raise AssertionError("Proxy closed before sending response headers")
        headers.extend(byte)
        if len(headers) > 65536:
            raise AssertionError("Proxy response headers exceeded the test limit")
    return bytes(headers)


def send_request(connection: socket.socket, target: str, body: bytes, headers: dict[str, str], *, port: int,
                 host: str = "127.0.0.1"
                 ) -> tuple[int, dict[str, str], bytes]:
    request_headers = {"Host": f"{host}:{port}", "Content-Length": str(len(body)), **headers}
    wire = f"POST {target} HTTP/1.1\r\n" + "".join(f"{name}: {value}\r\n" for name, value in request_headers.items())
    connection.sendall(wire.encode() + b"\r\n" + body)
    response = HTTPResponse(connection)
    try:
        response.begin()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        response.close()


@pytest.fixture
def egress(tmp_path: Path) -> Iterator[EgressHarness]:
    image = release_image_reference()
    if image is None and importlib.util.find_spec("mitmproxy") is None:
        message = "Security e2e requires: uv run --locked --project cvms/security --extra mitmproxy python -m pytest"
        if os.environ.get("UMBRA_E2E_REQUIRED") == "1":
            pytest.fail(message)
        pytest.skip(message)
    with ExitStack() as stack:
        harness = EgressHarness(tmp_path, stack)
        yield harness
        assert all(process.poll() is None for process in harness.processes), harness.sanitized_output()
        if harness.image_runtime:
            harness.image_runtime.assert_running()


@pytest.mark.parametrize("scheme", ["http", "https"], ids=["absolute-http", "connect-tls"])
def test_allowed_request_injection_and_redacted_traffic_success(egress: EgressHarness, scheme: str) -> None:
    """Both wire paths inject only at the proxy and emit contents-free logs."""
    status, _, body = egress.request(scheme=scheme, path=f"/allowed?credential={QUERY_VALUE}",
                                     headers={"Authorization": "Bearer sandbox-placeholder"})

    assert (status, body) == (200, RESPONSE_BODY)
    assert len(egress.origin.requests) == 1
    upstream = egress.origin.requests[0]
    assert upstream["headers"]["authorization"] == f"Bearer {INJECTED_VALUE}"
    assert "proxy-authorization" not in upstream["headers"]
    assert upstream["body"] == b"harmless-body"
    record = egress.wait_log(path="/allowed", decision="allowed", status=200)
    assert record["bytes_transferred"] == len(RESPONSE_BODY)
    published = json.dumps(egress.console.logs) + "\n".join(path.read_text() for path in egress.log_paths)
    for value in (PROXY_TOKEN, INGEST_TOKEN, EXPORT_TOKEN, INJECTED_VALUE, QUERY_VALUE, "harmless-body"):
        assert value not in published


def test_blocked_connect_origin_non_delivery_failure(egress: EgressHarness) -> None:
    """An explicitly blocked target returns a policy denial before delivery."""
    with egress.tunnel() as connection:
        connection.sendall(
            (f"CONNECT {egress.destination_host}:{egress.blocked_port} HTTP/1.1\r\nHost: {egress.destination_host}:{egress.blocked_port}\r\n"
             f"Proxy-Authorization: Bearer {PROXY_TOKEN}\r\n\r\n").encode()
        )
        response = HTTPResponse(connection)
        response.begin()
        assert response.status == 403
        assert response.getheader("X-Umbra-Block-Reason") == "blocked_destination"
        response.read()
        response.close()
    egress.wait_log(path="/", decision="blocked_destination", status=403)
    assert egress.origin.requests == []


@pytest.mark.parametrize("token", [None, "unknown-e2e-bearer"], ids=["missing", "unknown"])
def test_unauthenticated_connect_origin_non_delivery_failure(egress: EgressHarness, token: str | None) -> None:
    """Unknown identities cannot open tunnels or create attributed traffic logs."""
    with egress.tunnel() as connection:
        auth = "" if token is None else f"Proxy-Authorization: Bearer {token}\r\n"
        connection.sendall(
            (f"CONNECT {egress.destination_host}:{egress.https_port} HTTP/1.1\r\n"
             f"Host: {egress.destination_host}:{egress.https_port}\r\n{auth}\r\n").encode()
        )
        response = HTTPResponse(connection)
        response.begin()
        assert response.status == 407
        response.read()
        response.close()
    assert egress.origin.requests == []
    assert egress.console.logs == []


@pytest.mark.parametrize("location", ["body", "header", "gzip"], ids=["plaintext-body", "header", "compressed-body"])
def test_dlp_origin_non_delivery_failure(egress: EgressHarness, location: str) -> None:
    """TLS interception scans real header/body/decoded gzip bytes before egress."""
    body = DLP_VALUE.encode() if location != "header" else b"harmless-body"
    headers = {"X-Sandbox-Value": DLP_VALUE} if location == "header" else {}
    if location == "gzip":
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    status, response_headers, _ = egress.request(body=body, headers=headers)

    assert status == 403
    assert response_headers["x-umbra-block-reason"] == "dlp_secret_detected"
    egress.wait_log(path="/allowed", decision="dlp_secret_detected", status=403)
    assert egress.origin.requests == []
    published = json.dumps(egress.console.logs) + "\n".join(path.read_text() for path in egress.log_paths)
    assert DLP_VALUE not in published
    assert INJECTED_VALUE not in published


@pytest.mark.parametrize("change,expected_status", [("deny-all", 403), ("remove-cvm", 407)])
def test_control_revocation_on_existing_tls_connection_failure(
    egress: EgressHarness, change: str, expected_status: int,
) -> None:
    """A live CONNECT identity cannot keep old grants after the next real poll."""
    with egress.https_connection() as connection:
        assert egress.request(connection=connection)[0] == 200
        if change == "remove-cvm":
            entries = []
        else:
            policy = egress.policy()
            policy["allowed_destinations"] = []
            entries = egress.entries(policy)
        egress.console.replace(entries)
        assert egress.request(connection=connection)[0] == expected_status
    assert len(egress.origin.requests) == 1


def test_control_outage_retains_restrictions_and_recovers_success(egress: EgressHarness) -> None:
    """A real polling outage preserves the last valid policy until recovery."""
    assert egress.request()[0] == 200
    with egress.console.lock:
        egress.console.outage = True
    eventually(lambda: egress.console.failed_polls >= 2, message="Control polling did not encounter the outage")
    assert egress.request()[0] == 200
    status, headers, _ = egress.request(path="/forbidden")
    assert status == 403
    assert headers["x-umbra-block-reason"] == "destination_not_allowed"
    assert len(egress.origin.requests) == 2
    with egress.console.lock:
        egress.console.outage = False
    policy = egress.policy()
    policy["allowed_destinations"] = []
    egress.console.replace(egress.entries(policy))
    # A fresh CONNECT now fails at the host/port gate; use the plain HTTP path
    # to observe the current denial without attempting a TLS upgrade.
    assert egress.request(scheme="http")[0] == 403
    assert len(egress.origin.requests) == 2


def test_malformed_pulled_policy_origin_non_delivery_failure(egress: EgressHarness) -> None:
    """A bad real control response becomes deny-all without killing mitmdump."""
    assert egress.request(scheme="http")[0] == 200
    policy = egress.policy()
    policy["unexpected_policy_field"] = True
    egress.console.replace(egress.entries(policy))

    status, headers, _ = egress.request(scheme="http")

    assert status == 403
    assert headers["x-umbra-block-reason"] == "destination_not_allowed"
    assert len(egress.origin.requests) == 1
    egress.wait_log(path="/allowed", decision="destination_not_allowed", status=403)


def test_untrusted_upstream_tls_origin_non_delivery_failure(egress: EgressHarness, tmp_path: Path) -> None:
    """An allowlisted destination still needs a valid upstream certificate."""
    port = egress.untrusted_port
    if port is None:
        untrusted_directory = tmp_path / "untrusted-origin"
        untrusted_directory.mkdir()
        tls, _ = fixture_tls(untrusted_directory, egress.destination_host)
        port = egress.stack.enter_context(serve_http(egress.origin.handler(), tls))
    policy = egress.policy()
    rule = {"id": "allow.untrusted", "scheme": "https", "host": egress.destination_host, "ports": [port],
            "methods": ["POST"], "path_prefixes": ["/allowed"]}
    policy["allowed_destinations"].append(rule)
    policy["secret_injections"].append({
        "id": "inject.untrusted", "match": {key: value for key, value in rule.items() if key != "id"},
        "type": "request_header", "header": "authorization", "value": INJECTED_VALUE,
        "value_template": "Bearer ${secret}",
    })
    egress.console.replace(egress.entries(policy))

    status, _, _ = egress.request(port=port)

    assert status == 502
    assert egress.origin.requests == []


@pytest.mark.parametrize("image", ["", "ghcr.io/example/security:latest", "sha256:" + "a" * 64,
                                  "ghcr.io/example/security@sha256:" + "A" * 64])
def test_release_image_mutable_or_invalid_reference_failure(monkeypatch: pytest.MonkeyPatch, image: str) -> None:
    """An invalid image request cannot silently fall back to source execution."""
    monkeypatch.setenv("UMBRA_TEST_SECURITY_IMAGE", image)
    with pytest.raises(ValueError, match="immutable"):
        release_image_reference()


def test_release_image_docker_desktop_selection_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Container-local fixtures preserve exact image selection on Docker Desktop."""
    image = "ghcr.io/example/security@sha256:" + "a" * 64
    monkeypatch.setenv("UMBRA_TEST_SECURITY_IMAGE", image)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert release_image_reference() == image


def test_release_image_explicit_digest_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Linux release run preserves the exact caller-selected runtime digest."""
    image = "ghcr.io/example/security@sha256:" + "a" * 64
    monkeypatch.setenv("UMBRA_TEST_SECURITY_IMAGE", image)
    monkeypatch.setattr(sys, "platform", "linux")
    assert release_image_reference() == image


def test_release_container_private_environment_success(tmp_path: Path) -> None:
    """Synthetic credentials reach Docker through a private file, never argv."""
    runtime = ImageRuntime.__new__(ImageRuntime)
    runtime.image = "ghcr.io/example/security@sha256:" + "a" * 64
    runtime.directory = tmp_path
    runtime.network = "own-network"
    runtime.ingress_network = "own-ingress"
    runtime.names = []
    env = {"CONSOLE_INGEST_TOKEN": INGEST_TOKEN, "CA_EXPORT_TOKEN": EXPORT_TOKEN}
    command = runtime.command("mitmproxy", env, [], [], "umbra-security-mitmproxy")

    assert all(value not in " ".join(command) for value in env.values())
    env_file = Path(command[command.index("--env-file") + 1])
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert env_file.read_text() == "".join(f"{key}={value}\n" for key, value in env.items())


def test_release_image_cleanup_error_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A teardown error fails the gate after cleanup attempts every owned resource."""
    runtime = ImageRuntime.__new__(ImageRuntime)
    runtime.names = ["own-first", "own-second"]
    runtime.processes = []
    runtime.network = "own-network"
    runtime.ingress_network = "own-ingress"
    removed = []

    def docker(args: list[str]) -> str:
        removed.append(args[-1])
        if args[-1] == "own-second":
            raise RuntimeError("fixture teardown failure")
        return ""

    monkeypatch.setattr(runtime, "docker", docker)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        runtime.cleanup()
    assert removed == ["own-second", "own-first", "own-ingress", "own-network"]


@pytest.mark.parametrize("token", [None, INGEST_TOKEN, EXPORT_TOKEN], ids=["missing", "ingest", "export"])
def test_fixture_control_service_credentials_failure(token: str | None) -> None:
    """SC credentials cannot read counters or change the independent fixture state."""
    state = ContainerFixtureState({"ingest_token": INGEST_TOKEN}, secrets.token_urlsafe(32))
    with serve_http(state.handler("control")) as port, httpx.Client(trust_env=False, timeout=5) as client:
        headers = {} if token is None else {"Authorization": "Bearer " + token}
        read = client.get(f"http://127.0.0.1:{port}/state", headers=headers)
        write = client.post(f"http://127.0.0.1:{port}/control", headers=headers, json={"outage": True})
    assert (read.status_code, write.status_code, state.outage) == (401, 401, False)
