import pytest

from concrete_security_cvm.policy import (
    MAX_BODY_ASSERTION_BYTES,
    PolicyValidationError,
    parse_effective_policy,
)


FORM_HEADERS = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
JSON_HEADERS = {"content-type": "application/json; charset=utf-8"}


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


def slack_rule_with_assertions(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": "slack-read",
        "scheme": "https",
        "host": "slack.com",
        "ports": [443],
        "methods": ["POST"],
        "path_prefixes": ["/api/conversations.history"],
        "body_assertions": [
            {"kind": "form", "field": "/channel", "allow_values": ["C0ALLOWED1", "C0ALLOWED2"]}
        ],
        "traffic_log_attributes": [{"name": "slack_channel", "kind": "form", "field": "/channel"}],
    }
    rule.update(overrides)
    return rule


def test_body_assertion_form_match_allows_request() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0ALLOWED1&oldest=0",
        headers=FORM_HEADERS,
    )

    assert decision.allowed is True
    assert decision.matched_rule is not None
    assert decision.matched_rule.rule_id == "slack-read"


def test_body_assertion_form_mismatch_falls_through_to_deny() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0NOTALLOWED",
        headers=FORM_HEADERS,
    )

    assert decision.allowed is False
    assert decision.reason == "destination_not_allowed"


def test_body_assertion_wrong_content_type_denies() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0ALLOWED1",
        headers=JSON_HEADERS,
    )

    assert decision.allowed is False
    assert decision.reason == "destination_not_allowed"


def test_body_assertion_form_missing_field_denies() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"other=1",
        headers=FORM_HEADERS,
    )

    assert decision.allowed is False


@pytest.mark.parametrize(
    "path",
    [
        "/api/conversations.history/../chat.postMessage",
        "/api/conversations.history%2f..%2fchat.postMessage",
        "/api/conversations.history/%2e%2e/chat.postMessage",
        "/api/conversations.history\\..\\chat.postMessage",
        "/api/conversations.history//chat.postMessage",
    ],
)
def test_ambiguous_paths_do_not_match_allow_prefix(path: str) -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path=path,
        body=b"channel=C0ALLOWED1",
        headers=FORM_HEADERS,
    )

    assert decision.allowed is False
    assert decision.reason == "destination_not_allowed"


def test_encoded_slash_policy_prefix_allows_npm_scoped_package_path() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        {
            "id": "npm-scoped-package",
            "scheme": "https",
            "host": "registry.npmjs.org",
            "ports": [443],
            "methods": ["GET"],
            "path_prefixes": ["/@openclaw%2Fslack"],
        }
    ]
    policy = parse_effective_policy(raw)

    assert policy.decide(
        scheme="https",
        host="registry.npmjs.org",
        port=443,
        method="GET",
        path="/@openclaw%2fslack",
    ).allowed
    assert not policy.decide(
        scheme="https",
        host="registry.npmjs.org",
        port=443,
        method="GET",
        path="/@openclaw/slack",
    ).allowed


def test_ambiguous_policy_path_prefix_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions(path_prefixes=["/api/../chat.postMessage"])]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "invalid_path_prefix" for error in exc.value.errors)


def test_body_assertion_json_match_allows_request() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/channel", "allow_values": ["C0ALLOWED1"]}],
            traffic_log_attributes=[{"name": "slack_channel", "kind": "json", "field": "/channel"}],
        )
    ]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b'{"channel":"C0ALLOWED1","oldest":0}',
        headers=JSON_HEADERS,
    )

    assert decision.allowed is True
    assert decision.matched_rule is not None


def test_body_assertion_json_nested_path_resolves_scalar() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            id="notion-page",
            host="api.notion.com",
            path_prefixes=["/v1/databases/"],
            body_assertions=[
                {"kind": "json", "field": "/filter/property", "allow_values": ["Name"]}
            ],
            traffic_log_attributes=[],
        )
    ]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="api.notion.com",
        port=443,
        method="POST",
        path="/v1/databases/abc/query",
        body=b'{"filter":{"property":"Name","equals":"hi"}}',
        headers=JSON_HEADERS,
    )

    assert decision.allowed is True


def test_body_assertion_non_scalar_resolution_denies() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/filter", "allow_values": ["x"]}],
            traffic_log_attributes=[],
        )
    ]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b'{"filter":{"nested":"x"}}',
        headers=JSON_HEADERS,
    )

    assert decision.allowed is False


def test_body_assertion_malformed_json_denies() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/channel", "allow_values": ["C0ALLOWED1"]}],
            traffic_log_attributes=[],
        )
    ]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"{not json",
        headers=JSON_HEADERS,
    )

    assert decision.allowed is False


def test_body_assertion_deeply_nested_json_denies_without_recursion_error() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/channel", "allow_values": ["C0ALLOWED1"]}],
            traffic_log_attributes=[],
        )
    ]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=(b"[" * 100_000) + (b"]" * 100_000),
        headers=JSON_HEADERS,
    )

    assert decision.allowed is False


def test_body_assertion_oversized_body_denies() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0ALLOWED1&pad=" + b"A" * MAX_BODY_ASSERTION_BYTES,
        headers=FORM_HEADERS,
    )

    assert decision.allowed is False


def test_body_assertion_rule_without_assertions_still_matches() -> None:
    raw = sample_policy()
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="api.github.com",
        port=443,
        method="POST",
        path="/repos/x/y",
        body=b'{"channel":"anything"}',
    )

    assert decision.allowed is True
    assert decision.matched_rule is not None
    assert decision.matched_rule.body_assertions == ()


def test_traffic_log_attributes_extracted_on_allow() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_rule_with_assertions()]
    policy = parse_effective_policy(raw)

    decision = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0ALLOWED1",
        headers=FORM_HEADERS,
    )

    assert decision.matched_rule is not None
    attributes = decision.matched_rule.extract_traffic_log_attributes(b"channel=C0ALLOWED1", FORM_HEADERS)
    assert attributes == {"slack_channel": "C0ALLOWED1"}


def test_body_assertions_rejected_on_blocked_destinations() -> None:
    raw = sample_policy()
    raw["blocked_destinations"] = [
        {
            **raw["blocked_destinations"][0],  # type: ignore[index]
            "body_assertions": [{"kind": "form", "field": "/channel", "allow_values": ["x"]}],
        }
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.field.endswith(".body_assertions") for error in exc.value.errors)


def test_body_assertions_rejected_on_secret_injection_match() -> None:
    raw = sample_policy()
    raw["secret_injections"][0]["match"]["body_assertions"] = [  # type: ignore[index]
        {"kind": "form", "field": "/channel", "allow_values": ["x"]}
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any("body_assertions" in error.field for error in exc.value.errors)


def test_body_assertion_invalid_kind_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "yaml", "field": "/channel", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "invalid_kind" for error in exc.value.errors)


def test_body_assertion_form_pointer_must_be_single_segment() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "form", "field": "/foo/bar", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_body_assertion_json_pointer_max_4_segments() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/a/b/c/d/e", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_body_assertion_pointer_must_start_with_slash() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "form", "field": "channel", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_body_assertion_pointer_rejects_special_chars() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/foo~1bar", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_body_assertion_pointer_rejects_array_append_segment() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "json", "field": "/items/-", "allow_values": ["x"]}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_body_assertion_allow_values_must_be_non_empty() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "form", "field": "/channel", "allow_values": []}]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_traffic_log_attributes_duplicate_name_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            traffic_log_attributes=[
                {"name": "slack_channel", "kind": "form", "field": "/channel"},
                {"name": "slack_channel", "kind": "form", "field": "/channel"},
            ]
        )
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "duplicate_name" for error in exc.value.errors)


def test_traffic_log_attribute_name_must_be_lowercase() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            traffic_log_attributes=[
                {"name": "SlackChannel", "kind": "form", "field": "/channel"},
            ]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_unknown_field_in_body_assertion_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[
                {"kind": "form", "field": "/channel", "allow_values": ["x"], "extra": True}
            ]
        )
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "unknown_field" for error in exc.value.errors)


def test_first_allow_rule_must_match_or_fall_through() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_rule_with_assertions(
            body_assertions=[{"kind": "form", "field": "/channel", "allow_values": ["C0ALLOWED1"]}]
        ),
        slack_rule_with_assertions(
            id="slack-read-broad",
            body_assertions=[{"kind": "form", "field": "/channel", "allow_values": ["C0OTHER"]}],
            traffic_log_attributes=[],
        ),
    ]
    policy = parse_effective_policy(raw)

    matched = policy.decide(
        scheme="https",
        host="slack.com",
        port=443,
        method="POST",
        path="/api/conversations.history",
        body=b"channel=C0OTHER",
        headers=FORM_HEADERS,
    )

    assert matched.allowed is True
    assert matched.matched_rule is not None
    assert matched.matched_rule.rule_id == "slack-read-broad"
