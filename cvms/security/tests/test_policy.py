import pytest

from concrete_security_cvm.policy import PolicyValidationError, parse_effective_policy


def sample_policy() -> dict[str, object]:
    return {
        "allowed_destinations": [
            {
                "id": "allow.github",
                "scheme": "https",
                "host": "*.github.com",
                "ports": [443],
                "methods": ["GET", "POST"],
                "path_prefixes": ["/"],
            }
        ],
        "blocked_destinations": [
            {
                "id": "block.upload",
                "scheme": "https",
                "host": "uploads.github.com",
                "ports": [443],
                "methods": ["POST"],
                "path_prefixes": ["/"],
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
                "value": "sk-ant-secret",
                "value_template": "Bearer ${secret}",
            }
        ],
        "sandbox_env": [{"name": "ANTHROPIC_API_KEY", "value": "concrete-proxy-injected"}],
    }


def test_destination_policy_allows_wildcard_subdomain_but_not_apex() -> None:
    policy = parse_effective_policy(sample_policy())

    assert policy.decide(
        scheme="https",
        host="api.github.com",
        port=443,
        method="GET",
        path="/repos",
    ).allowed
    assert not policy.decide(
        scheme="https",
        host="github.com",
        port=443,
        method="GET",
        path="/",
    ).allowed


def test_blocked_destinations_precede_allow_rules() -> None:
    policy = parse_effective_policy(sample_policy())

    decision = policy.decide(
        scheme="https",
        host="uploads.github.com",
        port=443,
        method="POST",
        path="/asset",
    )

    assert decision.allowed is False
    assert decision.reason == "blocked_destination"
    assert decision.rule_id == "block.upload"


def test_injection_headers_render_after_match() -> None:
    policy = parse_effective_policy(sample_policy())

    headers = policy.render_injection_headers(
        scheme="https",
        host="api.anthropic.com",
        port=443,
        method="POST",
        path="/v1/messages",
    )

    assert headers == {"authorization": "Bearer sk-ant-secret"}


def test_conflicting_injections_fail_closed() -> None:
    raw = sample_policy()
    injections = list(raw["secret_injections"])  # type: ignore[arg-type]
    injections.append({**injections[0], "id": "anthropic-auth-2", "value": "different"})
    raw["secret_injections"] = injections
    policy = parse_effective_policy(raw)

    with pytest.raises(PolicyValidationError) as exc:
        policy.render_injection_headers(
            scheme="https",
            host="api.anthropic.com",
            port=443,
            method="POST",
            path="/v1/messages",
        )

    assert exc.value.errors[0].type == "secret_injection_conflict"


def test_unknown_policy_fields_are_invalid() -> None:
    raw = sample_policy()
    raw["max_egress_mbps"] = 10

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert exc.value.errors[0].field == "policy.max_egress_mbps"
    assert exc.value.errors[0].type == "unknown_field"


def test_invalid_destination_host_is_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [{**raw["allowed_destinations"][0], "host": "*.GitHub.com"}]  # type: ignore[index]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert exc.value.errors[0].type == "invalid_host"


def test_secret_patterns_are_compiled_with_re2() -> None:
    raw = sample_policy()
    raw["secret_patterns"] = [
        {
            "id": "backref",
            "name": "Backreference",
            "pattern": r"(a)\1",
            "scan_headers": True,
            "scan_body": True,
        }
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert exc.value.errors[0].type == "invalid_regex"
