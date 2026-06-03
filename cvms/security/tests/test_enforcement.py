from datetime import datetime, timezone
import hashlib

from concrete_security_cvm.control import ControlMap
import pytest

from concrete_security_cvm.enforcement import (
    DLPScanTimeout,
    ProxyRequest,
    enforce_authenticated_request,
    enforce_connect_request,
    enforce_request,
    find_dlp_match,
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


def control_map(policy_body: dict[str, object] | None = None) -> ControlMap:
    return ControlMap.from_console_payload(
        {
            "entries": [
                {
                    "cvm_id": "00000000-0000-4000-8000-000000000010",
                    "fqdn": "cvm-abc.dev.example.com",
                    "proxy_token_hash": hashlib.sha256(b"proxy-token").hexdigest(),
                    "merged_policy": policy() if policy_body is None else policy_body,
                    "policy_version": 3,
                    "updated_at": "2026-05-16T05:00:00Z",
                }
            ]
        }
    )


def request(**overrides: object) -> ProxyRequest:
    fields = {
        "source_ip": "10.0.0.5",
        "destination_ip": "160.79.104.10",
        "scheme": "https",
        "host": "api.anthropic.com",
        "port": 443,
        "method": "POST",
        "path": "/v1/messages",
        "headers": {
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
        },
        "body": b'{"message":"hello"}',
        "timestamp": datetime(2026, 5, 16, 5, 50, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return ProxyRequest(**fields)  # type: ignore[arg-type]


def test_missing_proxy_auth_fails_closed_without_traffic_log() -> None:
    result = enforce_request(request(headers={}), control_map())

    assert result.allowed is False
    assert result.response_code == 407
    assert result.reason == "proxy_auth_missing"
    assert result.traffic_log is None


def test_unknown_proxy_auth_fails_closed_without_traffic_log() -> None:
    result = enforce_request(request(headers={"Proxy-Authorization": "Bearer wrong-token"}), control_map())

    assert result.allowed is False
    assert result.response_code == 407
    assert result.reason == "proxy_auth_unknown"
    assert result.traffic_log is None


def test_allowed_request_strips_proxy_auth_and_injects_real_header_after_dlp() -> None:
    result = enforce_request(request(), control_map())

    assert result.allowed is True
    assert result.response_code is None
    assert "proxy-authorization" not in result.upstream_headers
    assert result.upstream_headers["authorization"] == "Bearer sk-ant-real"
    assert result.traffic_log is not None
    assert result.traffic_log.response_code is None
    assert result.traffic_log.cvm_id.hex == "00000000000040008000000000000010"


def test_encoded_slash_npm_scoped_package_request_is_allowed() -> None:
    registry_policy = {
        "allowed_destinations": [
            {
                "id": "npm-scoped-package",
                "scheme": "https",
                "host": "registry.npmjs.org",
                "ports": [443],
                "methods": ["GET"],
                "path_prefixes": ["/@openclaw%2Fslack"],
            }
        ],
        "blocked_destinations": [],
        "secret_patterns": [],
        "secret_injections": [],
        "sandbox_env": [],
    }

    result = enforce_request(
        request(
            host="registry.npmjs.org",
            destination_ip="104.16.24.34",
            method="GET",
            path="/@openclaw%2fslack",
            body=b"",
        ),
        control_map(registry_policy),
    )

    assert result.allowed is True


def test_wildcard_allowed_request_still_runs_injection_and_logs() -> None:
    policy_body = policy()
    policy_body["allowed_destinations"] = [
        {
            "id": "internet",
            "scheme": "https",
            "host": "*",
            "ports": [443],
            "methods": ["POST"],
            "path_prefixes": ["/"],
        }
    ]
    policy_body["blocked_destinations"] = []

    result = enforce_request(request(), control_map(policy_body))

    assert result.allowed is True
    assert result.response_code is None
    assert result.upstream_headers["authorization"] == "Bearer sk-ant-real"
    assert result.traffic_log is not None
    assert result.traffic_log.destination_host == "api.anthropic.com"
    assert result.matched_policy_id == "internet"


def test_wildcard_allowed_request_still_runs_dlp() -> None:
    policy_body = policy()
    policy_body["allowed_destinations"] = [
        {
            "id": "internet",
            "scheme": "https",
            "host": "*",
            "ports": [443],
            "methods": ["POST"],
            "path_prefixes": ["/"],
        }
    ]
    policy_body["blocked_destinations"] = []

    result = enforce_request(request(body=("ghp_" + ("A" * 36)).encode("utf-8")), control_map(policy_body))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "dlp_secret_detected"


def test_empty_allowed_destinations_air_gap_records_authenticated_denial() -> None:
    policy_body = policy()
    policy_body["allowed_destinations"] = []
    policy_body["blocked_destinations"] = []

    result = enforce_request(request(), control_map(policy_body))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "destination_not_allowed"
    assert result.traffic_log is not None
    assert result.traffic_log.response_code == 403


def test_authenticated_request_reuses_connect_identity_without_proxy_auth() -> None:
    cvm = control_map().lookup_proxy_token("proxy-token")
    assert cvm is not None

    result = enforce_authenticated_request(
        request(headers={"Authorization": "Bearer concrete-proxy-injected"}),
        cvm,
    )

    assert result.allowed is True
    assert result.response_code is None
    assert result.traffic_log is not None
    assert result.traffic_log.cvm_id.hex == "00000000000040008000000000000010"
    assert result.upstream_headers["authorization"] == "Bearer sk-ant-real"


def test_allowed_connect_uses_host_port_gate_and_records_tunnel_log() -> None:
    policy_body = policy()
    policy_body["blocked_destinations"] = []

    result = enforce_connect_request(request(method="CONNECT", path="/"), control_map(policy_body))

    assert result.allowed is True
    assert result.response_code is None
    assert result.traffic_log is not None
    assert result.traffic_log.method == "CONNECT"
    assert result.traffic_log.response_code == 200
    assert "proxy-authorization" not in result.upstream_headers
    assert result.upstream_headers["authorization"] == "Bearer concrete-proxy-injected"


def test_blocked_destination_returns_403_and_records_traffic_log() -> None:
    result = enforce_request(request(path="/v1/files/upload"), control_map())

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "blocked_destination"
    assert result.matched_policy_id == "block.upload"
    assert result.traffic_log is not None
    assert result.traffic_log.response_code == 403
    assert "proxy-authorization" not in result.upstream_headers


def test_blocked_connect_uses_host_port_gate_and_records_traffic_log() -> None:
    result = enforce_connect_request(request(method="CONNECT", path="/v1/messages"), control_map())

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "blocked_destination"
    assert result.matched_policy_id == "block.upload"
    assert result.traffic_log is not None
    assert result.traffic_log.method == "CONNECT"
    assert result.traffic_log.response_code == 403


def test_dlp_scans_sandbox_headers_before_secret_injection() -> None:
    leaked = "ghp_" + ("A" * 36)
    result = enforce_request(
        request(headers={"Proxy-Authorization": "Bearer proxy-token", "Authorization": leaked}),
        control_map(),
    )

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "dlp_secret_detected"
    assert result.matched_policy_id == "github-token"
    assert result.upstream_headers["authorization"] == leaked


def test_malformed_pulled_policy_denies_all() -> None:
    result = enforce_request(request(), control_map({"unknown": []}))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "destination_not_allowed"


def test_dlp_scan_deadline_is_enforced() -> None:
    entry = control_map().lookup_proxy_token("proxy-token")
    assert entry is not None
    ticks = iter([0.0, 1.0])

    with pytest.raises(DLPScanTimeout):
        find_dlp_match(
            entry.merged_policy.secret_patterns,
            {"authorization": "placeholder"},
            b"body",
            timeout_seconds=0.05,
            now=lambda: next(ticks),
        )


def test_dlp_timeout_blocks_authenticated_request() -> None:
    ticks = iter([0.0, 1.0])

    result = enforce_request(request(), control_map(), dlp_timeout_seconds=0.05, dlp_now=lambda: next(ticks))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "dlp_scan_timeout"


def test_dlp_scans_utf16_declared_body() -> None:
    # SD-01 round-2: a secret in a declared non-utf-8 charset must not evade the
    # utf-8-only scan; the destination would read it cleanly.
    leaked = "ghp_" + ("A" * 36)
    result = enforce_request(
        request(
            body=leaked.encode("utf-16"),
            headers={
                "Proxy-Authorization": "Bearer proxy-token",
                "Content-Type": "application/json; charset=utf-16",
            },
        ),
        control_map(),
    )

    assert result.allowed is False
    assert result.reason == "dlp_secret_detected"


def test_dlp_scans_utf16_undeclared_body_via_nul_strip() -> None:
    # Even with no declared charset, utf-16's interleaved NULs must not hide an
    # ASCII secret from the scanner.
    leaked = "ghp_" + ("A" * 36)
    result = enforce_request(request(body=leaked.encode("utf-16-le")), control_map())

    assert result.allowed is False
    assert result.reason == "dlp_secret_detected"


def test_dlp_undecodable_charset_fails_closed() -> None:
    # A declared charset the SC cannot decode means it cannot be sure it scanned
    # the plaintext the destination will read: block rather than allow.
    result = enforce_request(
        request(
            body=b"harmless",
            headers={
                "Proxy-Authorization": "Bearer proxy-token",
                "Content-Type": "text/plain; charset=made-up-codec",
            },
        ),
        control_map(),
    )

    assert result.allowed is False
    assert result.reason == "dlp_undecodable_body"


def slack_policy() -> dict[str, object]:
    return {
        "allowed_destinations": [
            {
                "id": "slack-read-conv-form",
                "scheme": "https",
                "host": "slack.com",
                "ports": [443],
                "methods": ["POST"],
                "path_prefixes": ["/api/conversations.history"],
                "body_assertions": [
                    {"kind": "form", "field": "/channel", "allow_values": ["C0ALLOWED1"]}
                ],
                "traffic_log_attributes": [
                    {"name": "slack_channel", "kind": "form", "field": "/channel"}
                ],
            },
            {
                "id": "slack-read-conv-json",
                "scheme": "https",
                "host": "slack.com",
                "ports": [443],
                "methods": ["POST"],
                "path_prefixes": ["/api/conversations.history"],
                "body_assertions": [
                    {"kind": "json", "field": "/channel", "allow_values": ["C0ALLOWED1"]}
                ],
                "traffic_log_attributes": [
                    {"name": "slack_channel", "kind": "json", "field": "/channel"}
                ],
            },
        ],
        "blocked_destinations": [],
        "secret_patterns": [],
        "secret_injections": [
            {
                "id": "slack-oauth-bearer",
                "match": {
                    "scheme": "https",
                    "host": "slack.com",
                    "ports": [443],
                    "methods": ["POST"],
                    "path_prefixes": ["/api/"],
                },
                "type": "request_header",
                "header": "authorization",
                "value": "xoxb-real-token",
                "value_template": "Bearer ${secret}",
            }
        ],
        "sandbox_env": [],
    }


def slack_request(**overrides: object) -> ProxyRequest:
    fields = {
        "source_ip": "10.0.0.5",
        "destination_ip": "1.2.3.4",
        "scheme": "https",
        "host": "slack.com",
        "port": 443,
        "method": "POST",
        "path": "/api/conversations.history",
        "headers": {
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": b"channel=C0ALLOWED1&limit=10",
        "timestamp": datetime(2026, 5, 16, 5, 50, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return ProxyRequest(**fields)  # type: ignore[arg-type]


def test_body_assertion_allowed_form_emits_attribute_in_traffic_log() -> None:
    result = enforce_request(slack_request(), control_map(slack_policy()))

    assert result.allowed is True
    assert result.matched_policy_id == "slack-read-conv-form"
    assert result.traffic_log is not None
    assert result.traffic_log.attributes == {"slack_channel": "C0ALLOWED1"}
    assert result.upstream_headers["authorization"] == "Bearer xoxb-real-token"


def test_body_assertion_form_with_wrong_content_type_denies() -> None:
    result = enforce_request(
        slack_request(headers={
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
            "Content-Type": "application/json",
        }),
        control_map(slack_policy()),
    )

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "body_assertion_failed"


@pytest.mark.parametrize(
    "path",
    [
        "/api/conversations.history/../chat.postMessage",
        "/api/conversations.history%2f..%2fchat.postMessage",
    ],
)
def test_ambiguous_slack_path_denies_before_injection(path: str) -> None:
    result = enforce_request(slack_request(path=path), control_map(slack_policy()))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "destination_not_allowed"
    assert result.upstream_headers["authorization"] == "Bearer concrete-proxy-injected"


def test_body_assertion_allowed_json_emits_attribute_in_traffic_log() -> None:
    result = enforce_request(
        slack_request(body=b'{"channel":"C0ALLOWED1"}', headers={
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
            "Content-Type": "application/json",
        }),
        control_map(slack_policy()),
    )

    assert result.allowed is True
    assert result.matched_policy_id == "slack-read-conv-json"
    assert result.traffic_log is not None
    assert result.traffic_log.attributes == {"slack_channel": "C0ALLOWED1"}


def test_body_assertion_unallowed_channel_denies_with_traffic_log() -> None:
    result = enforce_request(
        slack_request(body=b"channel=C0NOTALLOWED"),
        control_map(slack_policy()),
    )

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "body_assertion_failed"
    assert result.traffic_log is not None
    assert result.traffic_log.response_code == 403


def test_body_assertion_failure_is_ceiling_over_broad_allow_and_prevents_injection() -> None:
    policy_body = slack_policy()
    policy_body["allowed_destinations"].append(
        {
            "id": "internet",
            "scheme": "https",
            "host": "*",
            "ports": [443],
            "methods": ["POST"],
            "path_prefixes": ["/"],
        }
    )

    result = enforce_request(slack_request(body=b"channel=C0NOTALLOWED"), control_map(policy_body))

    assert result.allowed is False
    assert result.response_code == 403
    assert result.reason == "body_assertion_failed"
    assert result.matched_policy_id == "slack-read-conv-form"
    assert result.upstream_headers["authorization"] == "Bearer concrete-proxy-injected"


def test_body_assertion_malformed_body_denies() -> None:
    result = enforce_request(
        slack_request(body=b"{not json", headers={
            "Proxy-Authorization": "Bearer proxy-token",
            "Authorization": "Bearer concrete-proxy-injected",
            "Content-Type": "application/json",
        }),
        control_map(slack_policy()),
    )

    assert result.allowed is False
    assert result.response_code == 403


def test_body_assertion_missing_field_denies() -> None:
    result = enforce_request(
        slack_request(body=b"oldest=0&latest=100"),
        control_map(slack_policy()),
    )

    assert result.allowed is False
    assert result.response_code == 403


def test_allowed_path_without_assertions_emits_empty_attributes() -> None:
    result = enforce_request(request(), control_map())

    assert result.allowed is True
    assert result.traffic_log is not None
    assert result.traffic_log.attributes == {}
