from __future__ import annotations

from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from threading import Thread
from typing import Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from umbra_security_cvm.ca import generate_root_ca
from umbra_security_cvm.management_http import make_management_handler


@contextmanager
def management_server(ca_export_token: str = "export-token") -> Iterator[str]:
    ca = generate_root_ca()
    handler = make_management_handler(ca=ca, ca_export_token=ca_export_token)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_management_http_serves_ca_pem_with_exact_bearer() -> None:
    with management_server() as base_url:
        request = Request(f"{base_url}/ca.pem", headers={"Authorization": "Bearer export-token"})
        with urlopen(request, timeout=5) as response:
            body = response.read()
            headers = dict(response.headers.items())

    assert response.status == 200
    assert headers["Content-Type"] == "application/x-pem-file"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Length"] == str(len(body))
    assert b"BEGIN CERTIFICATE" in body
    assert b"PRIVATE KEY" not in body


def test_management_http_rejects_missing_or_wrong_bearer() -> None:
    with management_server() as base_url:
        for header in ({}, {"Authorization": "Bearer wrong"}):
            request = Request(f"{base_url}/ca.pem", headers=header)
            try:
                urlopen(request, timeout=5)
            except HTTPError as exc:
                assert exc.code == 401
                assert exc.headers["WWW-Authenticate"] == "Bearer"
                assert exc.headers["Cache-Control"] == "no-store"
                assert exc.read() == b""
            else:
                raise AssertionError("request unexpectedly succeeded")


def test_management_http_returns_404_for_other_paths_and_methods() -> None:
    with management_server() as base_url:
        for request in (
            Request(f"{base_url}/not-ca.pem", headers={"Authorization": "Bearer export-token"}),
            Request(
                f"{base_url}/ca.pem",
                data=b"",
                headers={"Authorization": "Bearer export-token"},
                method="POST",
            ),
        ):
            try:
                urlopen(request, timeout=5)
            except HTTPError as exc:
                assert exc.code == 404
                assert exc.headers["Cache-Control"] == "no-store"
                assert exc.read() == b""
            else:
                raise AssertionError("request unexpectedly succeeded")


def test_management_http_head_uses_auth_and_sends_no_body() -> None:
    with management_server() as base_url:
        request = Request(f"{base_url}/ca.pem", headers={"Authorization": "Bearer export-token"}, method="HEAD")
        with urlopen(request, timeout=5) as response:
            body = response.read()

    assert response.status == 200
    assert response.headers["Content-Type"] == "application/x-pem-file"
    assert response.headers["Cache-Control"] == "no-store"
    assert body == b""
