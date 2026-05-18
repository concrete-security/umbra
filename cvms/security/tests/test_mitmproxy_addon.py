from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
from typing import Mapping
from uuid import UUID

import pytest

from concrete_security_cvm.control import ControlMap
from concrete_security_cvm.control_loop import ControlPlaneState
from concrete_security_cvm.mitmproxy_addon import SecurityCVMProxyAddon
from concrete_security_cvm.traffic import TrafficLogClient, TrafficLogEmitter, TrafficLogQueue


CVM_ID = UUID("00000000-0000-4000-8000-000000000010")


@dataclass
class FakeResponse:
    status_code: int
    raw_content: bytes
    headers: Mapping[str, str]


@dataclass
class FakeConnection:
    address: tuple[str, int]
    ip_address: tuple[str, int] | None = None


class FakeRequest:
    def __init__(
        self,
        *,
        headers: dict[str, str] | None = None,
        method: str = "POST",
        scheme: str = "https",
        host: str = "api.anthropic.com",
        port: int = 443,
        path: str = "/v1/messages?api_key=not-logged",
        authority: str | None = None,
        pretty_url: str | None = None,
    ) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port
        self.method = method
        self.path = path
        self.authority = authority
        self.pretty_url = pretty_url
        self.headers = headers or {
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
        }
        self.raw_content = b'{"message":"hello"}'


class FakeFlow:
    def __init__(self, request: FakeRequest | None = None) -> None:
        self.request = request or FakeRequest()
        self.response: FakeResponse | None = None
        self.metadata: dict[str, object] = {}
        self.client_conn = FakeConnection(("10.0.0.5", 52344))
        self.server_conn = FakeConnection(("198.51.100.7", 443), ("198.51.100.7", 443))


def response_factory(status_code: int, content: bytes, headers: Mapping[str, str]) -> FakeResponse:
    return FakeResponse(status_code=status_code, raw_content=content, headers=headers)


def addon(policy_body: dict[str, object] | None = None) -> tuple[SecurityCVMProxyAddon, TrafficLogQueue]:
    queue = TrafficLogQueue(max_entries=100, max_bytes=100_000)
    client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest")
    emitter = TrafficLogEmitter(queue=queue, client=client)
    state = ControlPlaneState(control_map(policy_body))
    return (
        SecurityCVMProxyAddon(control_state=state, traffic_emitter=emitter, response_factory=response_factory),
        queue,
    )


def control_map(policy_body: dict[str, object] | None = None) -> ControlMap:
    return ControlMap.from_console_payload(
        {
            "entries": [
                {
                    "cvm_id": str(CVM_ID),
                    "fqdn": "cvm-abc.dev.example.com",
                    "proxy_token_hash": hashlib.sha256(b"proxy-token").hexdigest(),
                    "merged_policy": policy() if policy_body is None else policy_body,
                    "policy_version": 3,
                    "updated_at": "2026-05-16T06:20:00Z",
                }
            ]
        }
    )


def policy() -> dict[str, object]:
    return {
        "allowed_destinations": [
            {
                "id": "allow.anthropic",
                "scheme": "https",
                "host": "api.anthropic.com",
                "ports": [443],
                "methods": ["POST"],
                "path_prefixes": ["/v1/"],
            }
        ],
        "blocked_destinations": [
            {
                "id": "block.upload",
                "scheme": "https",
                "host": "api.anthropic.com",
                "ports": [443],
                "methods": ["POST"],
                "path_prefixes": ["/v1/files"],
            }
        ],
        "secret_patterns": [
            {
                "id": "github-token",
                "name": "GitHub token",
                "pattern": "gh[pousr]_[A-Za-z0-9]{36}",
                "scan_headers": True,
                "scan_body": True,
            }
        ],
        "secret_injections": [
            {
                "id": "anthropic-auth",
                "match": {
                    "scheme": "https",
                    "host": "api.anthropic.com",
                    "ports": [443],
                    "methods": ["POST"],
                    "path_prefixes": ["/v1/"],
                },
                "type": "request_header",
                "header": "authorization",
                "value": "sk-ant-real",
                "value_template": "Bearer ${secret}",
            }
        ],
        "sandbox_env": [],
    }


def test_allowed_request_strips_proxy_auth_injects_secret_and_logs_after_response() -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow()

    proxy_addon.request(flow)

    assert flow.response is None
    assert "Proxy-Authorization" not in flow.request.headers
    assert "proxy-authorization" not in flow.request.headers
    assert flow.request.headers["authorization"] == "Bearer sk-ant-real"
    assert len(queue) == 0

    flow.response = FakeResponse(status_code=201, raw_content=b'{"ok":true}', headers={})
    proxy_addon.response(flow)
    batch = queue.drain_batch()

    assert batch is not None
    assert len(batch.records) == 1
    log = batch.records[0]
    assert log.cvm_id == CVM_ID
    assert log.source_ip == "10.0.0.5"
    assert log.destination_ip == "198.51.100.7"
    assert log.path == "/v1/messages"
    assert log.response_code == 201
    assert log.bytes_transferred == len(b'{"ok":true}')
    assert "concrete_traffic_log" not in flow.metadata


def test_allowed_connect_uses_authority_and_does_not_log_before_http_request() -> None:
    policy_body = policy()
    policy_body["blocked_destinations"] = []
    proxy_addon, queue = addon(policy_body)
    flow = FakeFlow(FakeRequest(method="CONNECT", host="", path="/", pretty_url="api.anthropic.com:443"))

    proxy_addon.http_connect(flow)
    proxy_addon.request(flow)

    assert flow.response is None
    assert len(queue) == 0
    assert "Proxy-Authorization" not in flow.request.headers
    assert "proxy-authorization" not in flow.request.headers


def test_decrypted_https_request_reuses_connect_identity_without_proxy_auth() -> None:
    policy_body = policy()
    policy_body["blocked_destinations"] = []
    proxy_addon, queue = addon(policy_body)
    connect_flow = FakeFlow(FakeRequest(method="CONNECT", host="", path="/", authority="api.anthropic.com:443"))

    proxy_addon.http_connect(connect_flow)
    assert connect_flow.response is None
    flow = FakeFlow(FakeRequest(headers={"Authorization": "Bearer concrete-proxy-injected"}))
    flow.client_conn = connect_flow.client_conn
    proxy_addon.request(flow)

    assert flow.response is None
    assert flow.request.headers["authorization"] == "Bearer sk-ant-real"
    flow.response = FakeResponse(status_code=201, raw_content=b"{}", headers={})
    proxy_addon.response(flow)
    batch = queue.drain_batch()

    assert batch is not None
    assert len(batch.records) == 1
    assert batch.records[0].cvm_id == CVM_ID
    assert batch.records[0].method == "POST"
    assert batch.records[0].response_code == 201


def test_blocked_request_sets_403_and_emits_sanitized_traffic_log() -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow(FakeRequest(path="/v1/files/upload?secret=not-logged"))

    proxy_addon.request(flow)
    batch = queue.drain_batch()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.raw_content == b"Concrete Proxy: Destination blocked by policy\n"
    assert batch is not None
    assert batch.records[0].path == "/v1/files/upload"
    assert batch.records[0].response_code == 403


def test_blocked_connect_sets_403_and_emits_sanitized_traffic_log() -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow(FakeRequest(method="CONNECT", host="", path="/", authority="api.anthropic.com:443"))

    proxy_addon.http_connect(flow)
    batch = queue.drain_batch()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert batch is not None
    assert batch.records[0].method == "CONNECT"
    assert batch.records[0].response_code == 403


def test_unknown_proxy_bearer_returns_407_without_logging_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow(FakeRequest(headers={"Proxy-Authorization": "Bearer wrong-token"}))

    with caplog.at_level(logging.INFO, logger="concrete_security_cvm.mitmproxy_addon"):
        proxy_addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 407
    assert len(queue) == 0
    assert "wrong-token" not in caplog.text


def test_malformed_flow_returns_400_without_traffic_log() -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow()
    flow.request.host = ""

    proxy_addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 400
    assert len(queue) == 0


def test_error_hook_emits_502_for_allowed_request_without_response() -> None:
    proxy_addon, queue = addon()
    flow = FakeFlow()

    proxy_addon.request(flow)
    proxy_addon.error(flow)
    batch = queue.drain_batch()

    assert batch is not None
    assert len(batch.records) == 1
    assert batch.records[0].response_code == 502
    assert batch.records[0].bytes_transferred == 0
