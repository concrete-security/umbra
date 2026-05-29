from __future__ import annotations

import json

import pytest

from concrete_security_cvm.policy import (
    MAX_BODY_ASSERTION_BYTES,
    PolicyValidationError,
    parse_effective_policy,
)


def sample_policy() -> dict[str, object]:
    return {
        "allowed_destinations": [],
        "blocked_destinations": [],
        "secret_patterns": [],
        "secret_injections": [],
        "sandbox_env": [],
    }


def slack_socket_assertion(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "direction": "inbound",
        "when": {"/type": "events_api"},
        "require": {
            "/payload/event/channel": {"in": ["C0ALLOWED"]},
            "/payload/event/user": {"in": ["U0ALLOWED"]},
        },
        "on_violation": "drop",
        "on_drop_emit": {"envelope_id": "{/envelope_id}"},
    }
    entry.update(overrides)
    return entry


def slack_socket_rule(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": "slack-socket-mode",
        "scheme": "https",
        "host": "wss-primary.slack.com",
        "ports": [443],
        "methods": ["GET"],
        "path_prefixes": ["/"],
        "websocket_assertions": [slack_socket_assertion()],
    }
    rule.update(overrides)
    return rule


def policy_with_rule(**rule_overrides: object) -> object:
    raw = sample_policy()
    raw["allowed_destinations"] = [slack_socket_rule(**rule_overrides)]
    return parse_effective_policy(raw)


def decide(policy: object, content: bytes) -> object:
    return policy.decide_inbound_websocket(  # type: ignore[attr-defined]
        scheme="https", host="wss-primary.slack.com", port=443, content=content
    )


def events_api_frame(*, channel: str = "C0ALLOWED", user: str = "U0ALLOWED") -> bytes:
    return json.dumps(
        {
            "envelope_id": "env-123",
            "type": "events_api",
            "payload": {"event": {"channel": channel, "user": user, "text": "hi"}},
        }
    ).encode("utf-8")


def test_allowed_channel_and_sender_passes() -> None:
    verdict = decide(policy_with_rule(), events_api_frame())

    assert verdict is not None
    assert verdict.drop is False
    assert verdict.ack_frame is None


def test_blocked_channel_drops_and_renders_ack() -> None:
    verdict = decide(policy_with_rule(), events_api_frame(channel="C0BLOCKED"))

    assert verdict is not None
    assert verdict.drop is True
    assert verdict.ack_frame is not None
    assert json.loads(verdict.ack_frame.decode("utf-8")) == {"envelope_id": "env-123"}


def test_blocked_sender_drops() -> None:
    verdict = decide(policy_with_rule(), events_api_frame(user="U0OTHER"))

    assert verdict is not None
    assert verdict.drop is True


def test_selector_miss_passes() -> None:
    frame = json.dumps({"type": "hello", "payload": {}}).encode("utf-8")

    verdict = decide(policy_with_rule(), frame)

    assert verdict is None


def test_missing_required_field_fails_closed_and_drops() -> None:
    frame = json.dumps(
        {"envelope_id": "env-9", "type": "events_api", "payload": {"event": {"channel": "C0ALLOWED"}}}
    ).encode("utf-8")

    verdict = decide(policy_with_rule(), frame)

    assert verdict is not None
    assert verdict.drop is True
    assert verdict.ack_frame is not None
    assert json.loads(verdict.ack_frame.decode("utf-8")) == {"envelope_id": "env-9"}


def test_non_scalar_required_field_drops() -> None:
    frame = json.dumps(
        {
            "envelope_id": "env-7",
            "type": "events_api",
            "payload": {"event": {"channel": {"nested": "C0ALLOWED"}, "user": "U0ALLOWED"}},
        }
    ).encode("utf-8")

    verdict = decide(policy_with_rule(), frame)

    assert verdict is not None
    assert verdict.drop is True


def test_binary_non_json_frame_passes() -> None:
    verdict = decide(policy_with_rule(), b"\x00\x01\x02 not json")

    assert verdict is None


def test_malformed_json_frame_passes() -> None:
    verdict = decide(policy_with_rule(), b"{not valid json")

    assert verdict is None


def test_oversized_frame_passes() -> None:
    oversized = b'{"type":"events_api","pad":"' + b"A" * MAX_BODY_ASSERTION_BYTES + b'"}'

    verdict = decide(policy_with_rule(), oversized)

    assert verdict is None


def test_drop_without_emit_when_template_pointer_missing() -> None:
    frame = json.dumps(
        {"type": "events_api", "payload": {"event": {"channel": "C0BLOCKED", "user": "U0ALLOWED"}}}
    ).encode("utf-8")

    verdict = decide(policy_with_rule(), frame)

    assert verdict is not None
    assert verdict.drop is True
    assert verdict.ack_frame is None


def test_on_drop_emit_is_optional() -> None:
    policy = policy_with_rule(websocket_assertions=[slack_socket_assertion(on_drop_emit=None)])

    verdict = decide(policy, events_api_frame(channel="C0BLOCKED"))

    assert verdict is not None
    assert verdict.drop is True
    assert verdict.ack_frame is None


def test_rule_without_websocket_assertions_passes_everything() -> None:
    policy = policy_with_rule(websocket_assertions=[])

    assert decide(policy, events_api_frame(channel="C0BLOCKED")) is None
    assert decide(policy, b"anything") is None


def policy_with_rules(*rules: dict[str, object]) -> object:
    raw = sample_policy()
    raw["allowed_destinations"] = list(rules)
    return parse_effective_policy(raw)


def channel_filter_rule(rule_id: str, channel: str) -> dict[str, object]:
    return slack_socket_rule(
        id=rule_id,
        websocket_assertions=[
            slack_socket_assertion(
                require={
                    "/payload/event/channel": {"in": [channel]},
                    "/payload/event/user": {"in": ["U0ALLOWED"]},
                }
            )
        ],
    )


def broad_no_assertion_rule(rule_id: str) -> dict[str, object]:
    return slack_socket_rule(id=rule_id, host="*.slack.com", websocket_assertions=[])


@pytest.mark.parametrize("order", ["filter_first", "broad_first"])
def test_two_corules_drop_offlimits_regardless_of_order(order: str) -> None:
    filter_rule = channel_filter_rule("slack-filter", "C0ALLOWED")
    broad = broad_no_assertion_rule("slack-broad")
    rules = (filter_rule, broad) if order == "filter_first" else (broad, filter_rule)
    policy = policy_with_rules(*rules)

    blocked = decide(policy, events_api_frame(channel="C0BLOCKED"))
    assert blocked is not None
    assert blocked.drop is True

    allowed = decide(policy, events_api_frame(channel="C0ALLOWED"))
    assert allowed is not None
    assert allowed.drop is False


@pytest.mark.parametrize("order", ["filter_first", "broad_first"])
def test_broad_no_assertion_rule_does_not_bypass_filter(order: str) -> None:
    # A co-matching rule that grants the wss host but carries no assertions
    # contributes nothing to frame selection; it must not "allow all inbound".
    filter_rule = channel_filter_rule("slack-filter", "C0ALLOWED")
    broad = broad_no_assertion_rule("slack-broad")
    rules = (filter_rule, broad) if order == "filter_first" else (broad, filter_rule)
    policy = policy_with_rules(*rules)

    verdict = decide(policy, events_api_frame(channel="C0BLOCKED"))

    assert verdict is not None
    assert verdict.drop is True


def test_two_rules_different_channels_union_allows_each() -> None:
    policy = policy_with_rules(
        channel_filter_rule("slack-c1", "C1"),
        channel_filter_rule("slack-c2", "C2"),
    )

    c1 = decide(policy, events_api_frame(channel="C1"))
    assert c1 is not None and c1.drop is False

    c2 = decide(policy, events_api_frame(channel="C2"))
    assert c2 is not None and c2.drop is False

    blocked = decide(policy, events_api_frame(channel="C3"))
    assert blocked is not None and blocked.drop is True


def test_frame_no_assertion_selects_passes_under_union() -> None:
    policy = policy_with_rules(
        channel_filter_rule("slack-c1", "C1"),
        channel_filter_rule("slack-c2", "C2"),
    )
    frame = json.dumps({"type": "hello", "payload": {}}).encode("utf-8")

    assert decide(policy, frame) is None


def test_deeply_nested_json_frame_passes_without_recursion_error() -> None:
    policy = policy_with_rule()
    nested = (b"[" * 100_000) + (b"]" * 100_000)

    verdict = decide(policy, nested)

    assert verdict is None


def test_websocket_assertions_rejected_on_blocked_destinations() -> None:
    raw = sample_policy()
    raw["blocked_destinations"] = [slack_socket_rule()]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.field.endswith(".websocket_assertions") for error in exc.value.errors)


def test_websocket_assertions_rejected_on_secret_injection_match() -> None:
    raw = sample_policy()
    raw["secret_injections"] = [
        {
            "id": "slack-bearer",
            "match": {
                "scheme": "https",
                "host": "wss-primary.slack.com",
                "ports": [443],
                "methods": ["GET"],
                "path_prefixes": ["/"],
                "websocket_assertions": [slack_socket_assertion()],
            },
            "type": "request_header",
            "header": "authorization",
            "value": "xoxb-real",
            "value_template": "Bearer ${secret}",
        }
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any("websocket_assertions" in error.field for error in exc.value.errors)


def test_outbound_direction_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(direction="outbound")])
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "invalid_direction" for error in exc.value.errors)


def test_unknown_direction_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(direction="sideways")])
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "invalid_direction" for error in exc.value.errors)


def test_unknown_on_violation_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(on_violation="redact")])
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "invalid_on_violation" for error in exc.value.errors)


def test_require_must_use_in_matcher() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(
            websocket_assertions=[
                slack_socket_assertion(require={"/payload/event/channel": {"eq": "C0ALLOWED"}})
            ]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_require_pointer_special_char_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(
            websocket_assertions=[
                slack_socket_assertion(require={"/payload~1event": {"in": ["x"]}})
            ]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_require_pointer_segment_cap_enforced() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(
            websocket_assertions=[
                slack_socket_assertion(require={"/a/b/c/d/e": {"in": ["x"]}})
            ]
        )
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_unknown_websocket_assertion_field_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(extra=True)])
    ]

    with pytest.raises(PolicyValidationError) as exc:
        parse_effective_policy(raw)

    assert any(error.type == "unknown_field" for error in exc.value.errors)


def test_empty_when_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(when={})])
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)


def test_empty_require_rejected() -> None:
    raw = sample_policy()
    raw["allowed_destinations"] = [
        slack_socket_rule(websocket_assertions=[slack_socket_assertion(require={})])
    ]

    with pytest.raises(PolicyValidationError):
        parse_effective_policy(raw)
