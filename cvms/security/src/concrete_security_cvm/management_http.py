from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import os
from typing import Any
from urllib.parse import urlsplit

from concrete_security_cvm.ca import InMemoryRootCA, generate_root_ca
from concrete_security_cvm.management import ManagementResponse, handle_ca_pem_request


logger = logging.getLogger(__name__)


def make_management_handler(
    *,
    ca: InMemoryRootCA,
    ca_export_token: str,
) -> type[BaseHTTPRequestHandler]:
    if not ca_export_token:
        raise ValueError("ca_export_token is required")

    class SecurityCVMManagementHandler(BaseHTTPRequestHandler):
        server_version = "ConcreteSecurityCVMManagement/0.1"

        def do_GET(self) -> None:
            if urlsplit(self.path).path != "/ca.pem":
                self._send(ManagementResponse(status_code=404, headers={"Cache-Control": "no-store"}, body=b""))
                return
            response = handle_ca_pem_request(headers=self.headers, ca=ca, ca_export_token=ca_export_token)
            self._send(response)

        def do_HEAD(self) -> None:
            if urlsplit(self.path).path != "/ca.pem":
                self._send(ManagementResponse(status_code=404, headers={"Cache-Control": "no-store"}, body=b""))
                return
            response = handle_ca_pem_request(headers=self.headers, ca=ca, ca_export_token=ca_export_token)
            self._send(ManagementResponse(status_code=response.status_code, headers=response.headers, body=b""))

        def do_POST(self) -> None:
            self._send(ManagementResponse(status_code=404, headers={"Cache-Control": "no-store"}, body=b""))

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("management_http_request", extra={"client": self.client_address[0]})

        def _send(self, response: ManagementResponse) -> None:
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            if self.command != "HEAD" and response.body:
                self.wfile.write(response.body)

    return SecurityCVMManagementHandler


def serve_management_http(
    *,
    ca: InMemoryRootCA,
    ca_export_token: str,
    host: str = "0.0.0.0",
    port: int = 8081,
) -> None:
    handler = make_management_handler(ca=ca, ca_export_token=ca_export_token)
    with ThreadingHTTPServer((host, port), handler) as server:
        server.serve_forever()


def main() -> None:
    ca_export_token = os.environ.get("CA_EXPORT_TOKEN")
    if not ca_export_token:
        raise SystemExit("CA_EXPORT_TOKEN is required")
    host = os.environ.get("SC_MANAGEMENT_HOST", "0.0.0.0")
    port = int(os.environ.get("SC_MANAGEMENT_PORT", "8081"))
    serve_management_http(ca=generate_root_ca(), ca_export_token=ca_export_token, host=host, port=port)


if __name__ == "__main__":
    main()
