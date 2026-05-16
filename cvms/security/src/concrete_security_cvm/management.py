from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from concrete_security_cvm.ca import CAExportUnauthorized, InMemoryRootCA


@dataclass(frozen=True)
class ManagementResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


def handle_ca_pem_request(
    *,
    headers: Mapping[str, str],
    ca: InMemoryRootCA,
    ca_export_token: str,
) -> ManagementResponse:
    bearer = parse_bearer(headers.get("authorization") or headers.get("Authorization"))
    if bearer is None:
        return unauthorized_response()
    try:
        body = ca.export_ca_pem(supplied_token=bearer, ca_export_token=ca_export_token)
    except CAExportUnauthorized:
        return unauthorized_response()
    return ManagementResponse(
        status_code=200,
        headers={
            "Content-Type": "application/x-pem-file",
            "Cache-Control": "no-store",
        },
        body=body,
    )


def parse_bearer(value: str | None) -> str | None:
    if value is None:
        return None
    parts = value.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme != "Bearer" or not token or token.strip() != token or " " in token:
        return None
    return token


def unauthorized_response() -> ManagementResponse:
    return ManagementResponse(
        status_code=401,
        headers={
            "Cache-Control": "no-store",
            "WWW-Authenticate": "Bearer",
        },
        body=b"",
    )
