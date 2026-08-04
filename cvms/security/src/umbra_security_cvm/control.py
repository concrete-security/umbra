from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import logging
from types import MappingProxyType
from typing import Any
from uuid import UUID

import httpx


log = logging.getLogger(__name__)

from umbra_security_cvm.policy import EffectivePolicy, PolicyValidationError, parse_effective_policy, valid_proxy_token_hash


@dataclass(frozen=True)
class DevCVMControlEntry:
    cvm_id: UUID
    fqdn: str
    proxy_token_hash: str
    merged_policy: EffectivePolicy
    policy_version: int
    updated_at: str
    policy_error: str | None = None


@dataclass(frozen=True)
class ControlMap:
    entries_by_proxy_token_hash: MappingProxyType[str, DevCVMControlEntry]
    entry_errors: tuple[str, ...] = ()
    etag: str | None = None

    @classmethod
    def from_console_payload(cls, payload: Any, *, etag: str | None = None) -> ControlMap:
        errors: list[str] = []
        entries: dict[str, DevCVMControlEntry] = {}
        raw_entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(raw_entries, list):
            return cls(MappingProxyType({}), ("entries must be an array",), etag)
        for index, raw_entry in enumerate(raw_entries):
            entry = _parse_entry(raw_entry, index, errors)
            if entry is not None:
                entries[entry.proxy_token_hash] = entry
        return cls(MappingProxyType(entries), tuple(errors), etag)

    def lookup_proxy_token(self, token: str) -> DevCVMControlEntry | None:
        return self.entries_by_proxy_token_hash.get(hashlib.sha256(token.encode("utf-8")).hexdigest())

    def lookup_cvm_id(self, cvm_id: UUID) -> DevCVMControlEntry | None:
        for entry in self.entries_by_proxy_token_hash.values():
            if entry.cvm_id == cvm_id:
                return entry
        return None


@dataclass(frozen=True)
class PollResult:
    control_map: ControlMap | None
    etag: str | None
    not_modified: bool


class SCControlClient:
    def __init__(self, *, console_url: str, ingest_token: str, http: httpx.AsyncClient | None = None) -> None:
        if not console_url:
            raise ValueError("console_url is required")
        if not ingest_token:
            raise ValueError("ingest_token is required")
        self.console_url = console_url.rstrip("/")
        self.ingest_token = ingest_token
        self.http = http

    async def poll_once(self, *, etag: str | None = None) -> PollResult:
        headers = {"Authorization": f"Bearer {self.ingest_token}"}
        if etag is not None:
            headers["If-None-Match"] = etag
        if self.http is not None:
            response = await self.http.get(f"{self.console_url}/internal/sc-control/cvms", headers=headers)
        else:
            async with httpx.AsyncClient(timeout=10.0) as http:
                response = await http.get(f"{self.console_url}/internal/sc-control/cvms", headers=headers)
        next_etag = response.headers.get("ETag", etag)
        if response.status_code == 304:
            return PollResult(control_map=None, etag=next_etag, not_modified=True)
        response.raise_for_status()
        return PollResult(
            control_map=ControlMap.from_console_payload(response.json(), etag=next_etag),
            etag=next_etag,
            not_modified=False,
        )


def _parse_entry(raw: Any, index: int, errors: list[str]) -> DevCVMControlEntry | None:
    field = f"entries.{index}"
    if not isinstance(raw, dict):
        errors.append(f"{field}: entry must be an object")
        return None
    try:
        cvm_id = UUID(str(raw["cvm_id"]))
        fqdn = str(raw["fqdn"])
        proxy_token_hash = str(raw["proxy_token_hash"])
        policy_version = int(raw["policy_version"])
        updated_at = _parse_updated_at(raw["updated_at"])
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"{field}: malformed entry: {exc}")
        return None
    if not fqdn:
        errors.append(f"{field}.fqdn: empty fqdn")
        return None
    if not valid_proxy_token_hash(proxy_token_hash):
        errors.append(f"{field}.proxy_token_hash: must be 64 lower-case hex chars")
        return None
    if policy_version < 0:
        errors.append(f"{field}.policy_version: must be non-negative")
        return None
    try:
        policy = parse_effective_policy(raw.get("merged_policy"))
        policy_error = None
    except PolicyValidationError as exc:
        policy = EffectivePolicy.deny_all()
        policy_error = str(exc)
        errors.append(f"{field}.merged_policy: {policy_error}")
        log.error(
            "merged_policy_invalid",
            extra={"cvm_id": str(cvm_id), "policy_error": policy_error},
        )
    return DevCVMControlEntry(
        cvm_id=cvm_id,
        fqdn=fqdn,
        proxy_token_hash=proxy_token_hash,
        merged_policy=policy,
        policy_version=policy_version,
        updated_at=updated_at,
        policy_error=policy_error,
    )


def _parse_updated_at(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("updated_at must be a timestamp string")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value
