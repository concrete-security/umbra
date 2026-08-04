from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from umbra_console.config import load_settings

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4/"
DNS_HOST_RE = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"


class CloudflareError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        http_status: int | None = None,
        cloudflare_codes: tuple[int, ...] = (),
        field: str | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.cloudflare_codes = cloudflare_codes
        self.field = field


@dataclass(frozen=True)
class CloudflareRecord:
    id: str
    type: str
    name: str
    content: str


@dataclass(frozen=True)
class CloudflareClient:
    api_token: str
    zone_id: str
    api_base: str = CLOUDFLARE_API_BASE
    timeout_seconds: float = 20.0
    transport: httpx.AsyncBaseTransport | None = None

    @classmethod
    def from_settings(cls, *, zone_id_key: str = "CLOUDFLARE_ZONE_ID") -> CloudflareClient:
        raw = load_settings().raw
        api_token = raw.get("CLOUDFLARE_API_TOKEN", "").strip()
        zone_id = raw.get(zone_id_key, "").strip()
        if not api_token or not zone_id:
            raise CloudflareError("not_configured")
        api_base = raw.get("CLOUDFLARE_API_BASE", "").strip() or CLOUDFLARE_API_BASE
        if api_base != CLOUDFLARE_API_BASE and raw.get("OIDC_OVERRIDES_ALLOWED", "").lower() != "true":
            raise CloudflareError("override_not_allowed")
        return cls(api_token=api_token, zone_id=zone_id, api_base=api_base)

    async def find_records(self, *, name: str, record_type: str) -> list[CloudflareRecord]:
        validate_record_type(record_type)
        payload = await self._request(
            "GET",
            f"zones/{self.zone_id}/dns_records",
            params={"name": name, "type": record_type},
        )
        result = payload.get("result")
        if not isinstance(result, list):
            raise CloudflareError("invalid_response", field="result")
        return [record_from_payload(row) for row in result]

    async def ensure_dstack_txt(self, *, fqdn: str, app_id: str) -> str:
        return await self.ensure_record(
            record_type="TXT",
            name=dstack_txt_name(fqdn),
            content=f"{app_id}:443",
        )

    async def ensure_gateway_cname(self, *, fqdn: str, gateway_host: str) -> str:
        return await self.ensure_record(
            record_type="CNAME",
            name=fqdn,
            content=gateway_cname_content(gateway_host),
        )

    async def ensure_record(self, *, record_type: str, name: str, content: str) -> str:
        records = await self.find_records(name=name, record_type=record_type)
        for record in records:
            if record.content == content:
                return record.id
        if records:
            raise CloudflareError("record_conflict")
        payload = await self._request(
            "POST",
            f"zones/{self.zone_id}/dns_records",
            json=record_create_payload(record_type=record_type, name=name, content=content),
        )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise CloudflareError("invalid_response", field="result")
        return record_from_payload(result).id

    async def delete_record(self, record_id: str) -> None:
        if not record_id:
            raise CloudflareError("invalid_record_id")
        await self._request("DELETE", f"zones/{self.zone_id}/dns_records/{record_id}", tolerate_404=True)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        tolerate_404: bool = False,
    ) -> dict[str, Any]:
        url = urljoin(ensure_trailing_slash(self.api_base), path)
        async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport) as client:
            response = await client.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"},
                params=params,
                json=json,
            )
        if tolerate_404 and response.status_code == 404:
            return {"success": True, "result": None}
        try:
            payload = response.json()
        except ValueError as exc:
            raise CloudflareError("invalid_json", http_status=response.status_code) from exc
        if response.status_code < 200 or response.status_code >= 300 or payload.get("success") is not True:
            raise CloudflareError(
                "api_error",
                http_status=response.status_code,
                cloudflare_codes=cloudflare_error_codes(payload),
            )
        return payload


def record_create_payload(*, record_type: str, name: str, content: str) -> dict[str, Any]:
    validate_record_type(record_type)
    payload: dict[str, Any] = {
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": 1,
    }
    if record_type == "CNAME":
        payload["proxied"] = False
    return payload


def record_from_payload(payload: Any) -> CloudflareRecord:
    if not isinstance(payload, dict):
        raise CloudflareError("invalid_response")
    record_id = payload.get("id")
    record_type = payload.get("type")
    name = payload.get("name")
    content = payload.get("content")
    if not isinstance(record_id, str) or not record_id:
        raise CloudflareError("invalid_response", field="id")
    if record_type not in {"TXT", "CNAME"}:
        raise CloudflareError("invalid_response", field="type")
    if not isinstance(name, str) or not name:
        raise CloudflareError("invalid_response", field="name")
    if not isinstance(content, str) or not content:
        raise CloudflareError("invalid_response", field="content")
    return CloudflareRecord(id=record_id, type=record_type, name=name, content=content)


def dstack_txt_name(fqdn: str) -> str:
    validate_hostname(fqdn)
    return f"_dstack-app-address.{fqdn}"


def gateway_cname_content(gateway_host: str) -> str:
    validate_hostname(gateway_host)
    return f"_.{gateway_host}"


def validate_hostname(hostname: str) -> None:
    import re

    if not re.fullmatch(DNS_HOST_RE, hostname):
        raise CloudflareError("invalid_hostname")


def validate_record_type(record_type: str) -> None:
    if record_type not in {"TXT", "CNAME"}:
        raise CloudflareError("invalid_record_type")


def cloudflare_error_codes(payload: Any) -> tuple[int, ...]:
    if not isinstance(payload, dict):
        return ()
    errors = payload.get("errors", [])
    if not isinstance(errors, list):
        return ()
    codes: list[int] = []
    for error in errors:
        if isinstance(error, dict) and isinstance(error.get("code"), int):
            codes.append(error["code"])
    return tuple(codes)


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"
