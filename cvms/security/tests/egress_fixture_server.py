"""Container-local Console/origin fixtures, controlled only by the test runner.

This standalone stdlib module is mounted into a separate fixture container.
It is never imported or mounted by the Security CVM production containers.
"""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import ssl
import sys
from threading import Lock, Thread


class State:
    def __init__(self, config: dict, admin_token: str) -> None:
        self.lock = Lock()
        self.admin_token = admin_token
        self.ingest_token = config["ingest_token"]
        self.entries: list[dict] = []
        self.version = 0
        self.applied_etag = None
        self.outage = False
        self.failed_polls = 0
        self.rejected_auth = 0
        self.logs: list[dict] = []
        self.ingested_batches: set[str] = set()
        self.requests: list[dict] = []

    def handler(self, kind: str) -> type[BaseHTTPRequestHandler]:
        state = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:
                pass

            def respond(self, status: int, payload: dict | None = None, *, etag: str | None = None) -> None:
                data = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                if etag is not None:
                    self.send_header("ETag", etag)
                self.end_headers()
                self.wfile.write(data)

            def authenticated(self, token: str) -> bool:
                if hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                    return True
                self.respond(401)
                return False

            def body(self) -> bytes:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 1024 * 1024:
                    raise ValueError("invalid fixture request length")
                return self.rfile.read(size)

            def do_GET(self) -> None:
                if kind == "control":
                    if not self.authenticated(state.admin_token):
                        return
                    if self.path != "/state":
                        self.respond(404)
                        return
                    with state.lock:
                        self.respond(200, {
                            "version": state.version, "applied_etag": state.applied_etag,
                            "outage": state.outage, "failed_polls": state.failed_polls,
                            "logs": state.logs, "rejected_auth": state.rejected_auth,
                            "requests": state.requests,
                        })
                    return
                if kind != "console":
                    self.respond(404)
                    return
                if not self.authenticated(state.ingest_token):
                    with state.lock:
                        state.rejected_auth += 1
                    return
                if self.path != "/internal/sc-control/cvms":
                    self.respond(404)
                    return
                with state.lock:
                    if state.outage:
                        state.failed_polls += 1
                        self.respond(503)
                    else:
                        etag = f'"e2e-{state.version}"'
                        if self.headers.get("If-None-Match") == etag:
                            state.applied_etag = etag
                            self.respond(304, etag=etag)
                        else:
                            self.respond(200, {"entries": state.entries}, etag=etag)

            def do_POST(self) -> None:
                if kind == "origin":
                    body = self.body()
                    with state.lock:
                        state.requests.append({
                            "path": self.path,
                            "headers": {key.lower(): value for key, value in self.headers.items()},
                            "body_base64": base64.b64encode(body).decode(),
                        })
                    # Match the native origin's exact response bytes.
                    self.send_response(200)
                    self.send_header("Content-Length", "11")
                    self.end_headers()
                    self.wfile.write(b'{"ok":true}')
                    return
                if kind == "control":
                    if not self.authenticated(state.admin_token):
                        return
                    if self.path != "/control":
                        self.respond(404)
                        return
                    payload = json.loads(self.body())
                    with state.lock:
                        if "entries" in payload:
                            state.entries = payload["entries"]
                            state.version += 1
                            state.applied_etag = None
                        if "outage" in payload:
                            state.outage = bool(payload["outage"])
                        self.respond(200, {"version": state.version})
                    return
                if not self.authenticated(state.ingest_token):
                    with state.lock:
                        state.rejected_auth += 1
                    return
                if self.path != "/internal/traffic-logs":
                    self.respond(404)
                    return
                payload = json.loads(self.body())
                with state.lock:
                    if payload["idempotency_key"] not in state.ingested_batches:
                        state.logs.extend(payload["logs"])
                        state.ingested_batches.add(payload["idempotency_key"])
                self.respond(200, {"accepted": True})

        return Handler


def main() -> None:
    config = json.loads(Path(sys.argv[1]).read_text())
    token = os.environ.pop("UMBRA_FIXTURE_CONTROL_TOKEN")
    if len(token) < 32:
        raise ValueError("private fixture control token is required")
    state = State(config, token)
    contexts = {}
    for issuer in ("trusted", "untrusted"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config[issuer + "_cert"], config[issuer + "_key"])
        contexts[issuer] = context
    servers = []
    for port, kind, issuer in (
        (8083, "origin", None), (8443, "origin", "trusted"),
        (8444, "origin", "trusted"), (8445, "origin", "untrusted"),
        (8446, "console", "trusted"), (8089, "control", None),
    ):
        server = ThreadingHTTPServer(("0.0.0.0", port), state.handler(kind))
        server.daemon_threads = True
        if issuer:
            server.socket = contexts[issuer].wrap_socket(server.socket, server_side=True)
        servers.append(server)
        if kind != "control":
            Thread(target=server.serve_forever, daemon=True).start()
    # Every listener is bound before the control readiness endpoint can answer.
    servers[-1].serve_forever()


if __name__ == "__main__":
    main()
