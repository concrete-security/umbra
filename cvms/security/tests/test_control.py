import hashlib
import asyncio
from uuid import UUID

import httpx

from concrete_security_cvm.control import ControlMap, SCControlClient


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
