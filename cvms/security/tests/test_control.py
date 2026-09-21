import hashlib
import asyncio
from uuid import UUID

import httpx

from umbra_security_cvm.control import ControlMap, SCControlClient


def policy() -> dict[str, object]:
    return {
        "allowed_destinations": [
            {
                "id": "allow.github",
                "scheme": "https",
                "host": "*.github.com",
                "ports": [443],
                "methods": ["GET"],
                "path_prefixes": ["/"],
            }
        ],
        "blocked_destinations": [],
        "secret_patterns": [],
        "secret_injections": [],
        "sandbox_env": [],
    }


def entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "cvm_id": "00000000-0000-4000-8000-000000000010",
        "fqdn": "cvm-abc.dev.example.com",
        "proxy_token_hash": hashlib.sha256(b"proxy-token").hexdigest(),
        "merged_policy": policy(),
        "policy_version": 3,
        "updated_at": "2026-05-16T05:00:00Z",
    }
    base.update(overrides)
    return base


def test_control_map_resolves_proxy_token_hash() -> None:
    control_map = ControlMap.from_console_payload({"entries": [entry()]}, etag='"abc"')

    resolved = control_map.lookup_proxy_token("proxy-token")

    assert resolved is not None
    assert resolved.cvm_id == UUID("00000000-0000-4000-8000-000000000010")
    assert resolved.merged_policy.decide(
        scheme="https",
        host="api.github.com",
        port=443,
        method="GET",
        path="/repos",
    ).allowed
    assert control_map.lookup_proxy_token("wrong-token") is None


def test_control_map_accepts_old_and_new_proxy_tokens_during_overlap() -> None:
    cvm_id = "00000000-0000-4000-8000-000000000010"
    control_map = ControlMap.from_console_payload(
        {
            "entries": [
                entry(cvm_id=cvm_id, proxy_token_hash=hashlib.sha256(b"old-token").hexdigest()),
                entry(cvm_id=cvm_id, proxy_token_hash=hashlib.sha256(b"new-token").hexdigest()),
            ]
        }
    )

    assert control_map.lookup_proxy_token("old-token") is not None
    assert control_map.lookup_proxy_token("new-token") is not None
    assert len(control_map.entries_by_proxy_token_hash) == 2


def test_control_map_drops_malformed_policy_to_deny_all() -> None:
    control_map = ControlMap.from_console_payload({"entries": [entry(merged_policy={"unknown": []})]})

    resolved = control_map.lookup_proxy_token("proxy-token")

    assert resolved is not None
    assert resolved.policy_error is not None
    assert not resolved.merged_policy.decide(
        scheme="https",
        host="api.github.com",
        port=443,
        method="GET",
        path="/",
    ).allowed


def test_sc_control_client_sends_auth_and_etag() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"ETag": '"next"'}, json={"entries": [entry()]})

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = SCControlClient(console_url="https://console.example.com/", ingest_token="ingest", http=http)
            return await client.poll_once(etag='"old"')

    result = asyncio.run(run())

    assert result.etag == '"next"'
    assert result.control_map is not None
    assert result.not_modified is False
    assert requests[0].url == "https://console.example.com/internal/sc-control/cvms"
    assert requests[0].headers["authorization"] == "Bearer ingest"
    assert requests[0].headers["if-none-match"] == '"old"'


def test_sc_control_client_handles_not_modified() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(304, headers={"ETag": '"same"'})

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = SCControlClient(console_url="https://console.example.com", ingest_token="ingest", http=http)
            return await client.poll_once(etag='"same"')

    result = asyncio.run(run())

    assert result.not_modified is True
    assert result.control_map is None
    assert result.etag == '"same"'


def local_entry(seconds=300):
    from datetime import datetime, timedelta, timezone
    value = entry()
    value["local_workspace_id"] = value.pop("cvm_id")
    value.pop("fqdn")
    value["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    return value


def test_local_identity_and_traffic_success():
    """An admitted local bearer applies the profile and produces a distinct log ID."""
    from umbra_security_cvm.enforcement import ProxyRequest, enforce_request
    control = ControlMap.from_console_payload({"entries": [], "local_entries": [local_entry()]})
    result = enforce_request(ProxyRequest(source_ip="127.0.0.1", destination_ip="198.51.100.1",
        scheme="https", host="api.github.com", port=443, method="GET", path="/repos",
        headers={"Proxy-Authorization": "Bearer proxy-token"}), control)
    payload = result.traffic_log.to_json()
    assert result.allowed and payload["cvm_id"] is None and payload["local_workspace_id"] == local_entry()["local_workspace_id"]


def test_local_stale_control_expiry_failure():
    """A stale control snapshot cannot preserve bearer or CONNECT identity past expiry."""
    control = ControlMap.from_console_payload({"entries": [], "local_entries": [local_entry(-1)]})
    assert control.lookup_proxy_token("proxy-token") is None and control.lookup_cvm_id(UUID(local_entry()["local_workspace_id"])) is None


def test_local_missing_expiry_failure():
    """A partial/old local identity document never creates an unbounded lease."""
    value = local_entry()
    value.pop("expires_at")
    control = ControlMap.from_console_payload({"entries": [], "local_entries": [value]})
    assert control.lookup_proxy_token("proxy-token") is None
