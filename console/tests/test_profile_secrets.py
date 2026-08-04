import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from umbra_console.profile_secrets import (
    decrypt_profile_secret_value,
    decrypt_user_secret_value,
    encrypt_profile_secret_value,
    encrypt_user_secret_value,
    expand_policy_secret_values_for_owner,
    expand_profile_policy_secret_values,
    host_pattern_covers,
    redacted_profile_policy,
    secret_hosts_cover,
    split_profile_policy_secret_values,
    user_secret_references,
    valid_secret_host_pattern,
)

TEST_KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_profile_secret_values_are_encrypted_and_bound_to_profile(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)

    ciphertext = encrypt_profile_secret_value(
        profile_id="profile-a",
        injection_id="anthropic-key",
        value="sk-ant-real-secret",
    )

    assert "sk-ant-real-secret" not in ciphertext
    assert decrypt_profile_secret_value(
        profile_id="profile-a",
        injection_id="anthropic-key",
        ciphertext=ciphertext,
    ) == "sk-ant-real-secret"
    with pytest.raises(InvalidTag):
        decrypt_profile_secret_value(
            profile_id="profile-b",
            injection_id="anthropic-key",
            ciphertext=ciphertext,
        )


def test_split_profile_policy_secret_values_removes_values() -> None:
    policy = {
        "secret_injections": [
            {
                "id": "anthropic-key",
                "match": {"scheme": "https"},
                "type": "request_header",
                "header": "authorization",
                "value": "sk-ant-real-secret",
                "value_template": "Bearer ${secret}",
                "debug": "private",
            }
        ]
    }

    public_policy, values = split_profile_policy_secret_values(policy)

    assert values == {"anthropic-key": "sk-ant-real-secret"}
    assert public_policy == {
        "secret_injections": [
            {
                "id": "anthropic-key",
                "match": {"scheme": "https"},
                "type": "request_header",
                "header": "authorization",
                "value_template": "Bearer ${secret}",
            }
        ]
    }


def test_expand_profile_policy_secret_values_only_uses_encrypted_material(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    ciphertext = encrypt_profile_secret_value(
        profile_id="profile-a",
        injection_id="anthropic-key",
        value="sk-ant-real-secret",
    )

    expanded = expand_profile_policy_secret_values(
        profile_id="profile-a",
        policy={
            "secret_injections": [
                {
                    "id": "anthropic-key",
                    "type": "request_header",
                    "header": "authorization",
                    "value": "legacy-plaintext-ignored",
                    "value_template": "Bearer ${secret}",
                }
            ]
        },
        secret_material={"anthropic-key": ciphertext},
    )

    assert expanded["secret_injections"][0]["value"] == "sk-ant-real-secret"


def _user_injection(**overrides):
    injection = {
        "id": "slack-token",
        "match": {"scheme": "https", "host": "api.slack.com", "ports": [443], "methods": ["POST"], "path_prefixes": ["/"]},
        "type": "request_header",
        "header": "authorization",
        "value_from": {"user_secret": "slack-user-token"},
        "value_template": "Bearer ${secret}",
    }
    injection.update(overrides)
    return injection


def _full_match(*, host: str, scheme: str = "https") -> dict:
    return {"scheme": scheme, "host": host, "ports": [443], "methods": ["POST"], "path_prefixes": ["/"]}


def _owner_secrets(*, user_id="user-a", name="slack-user-token", value="xoxp-alice", allowed_hosts=None):
    return {
        name: {
            "ciphertext": encrypt_user_secret_value(user_id=user_id, name=name, value=value),
            "allowed_hosts": allowed_hosts if allowed_hosts is not None else ["api.slack.com"],
        }
    }


def _scan_for_key(value, key):
    if isinstance(value, dict):
        return key in value or any(_scan_for_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_scan_for_key(item, key) for item in value)
    return False


def test_user_secret_values_are_encrypted_and_bound_to_user_and_name(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)

    ciphertext = encrypt_user_secret_value(user_id="user-a", name="slack-user-token", value="xoxp-alice")

    assert "xoxp-alice" not in ciphertext
    assert (
        decrypt_user_secret_value(user_id="user-a", name="slack-user-token", ciphertext=ciphertext)
        == "xoxp-alice"
    )
    with pytest.raises(InvalidTag):
        decrypt_user_secret_value(user_id="user-b", name="slack-user-token", ciphertext=ciphertext)
    with pytest.raises(InvalidTag):
        decrypt_user_secret_value(user_id="user-a", name="other-name", ciphertext=ciphertext)


def test_user_and_profile_secret_aads_are_distinct_families(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)

    profile_ciphertext = encrypt_profile_secret_value(profile_id="x", injection_id="y", value="secret")

    with pytest.raises(InvalidTag):
        decrypt_user_secret_value(user_id="x", name="y", ciphertext=profile_ciphertext)


def test_host_pattern_shared_vector() -> None:
    # Cross-language verdict vector for the host-binding grammar.
    # `valid_secret_host_pattern` here is authoritative; the CLI ships a
    # client-side pre-flight mirror (valid_secret_host_pattern in
    # cli/src/commands/secret.rs) asserted against this SAME fixture by the Rust
    # test host_pattern_grammar_matches_shared_vector, so the two grammars cannot
    # drift silently.
    vector_path = Path(__file__).resolve().parents[2] / "testdata" / "secret_host_patterns.json"
    cases = json.loads(vector_path.read_text())["cases"]
    assert cases, "shared host-pattern vector is empty"
    for case in cases:
        assert valid_secret_host_pattern(case["pattern"]) is case["valid"], (
            f"host pattern {case['pattern']!r} expected valid={case['valid']}"
        )


@pytest.mark.parametrize(
    ("secret_pattern", "injection_host", "covers"),
    [
        ("api.x.com", "api.x.com", True),
        ("*.x.com", "a.x.com", True),
        ("*.x.com", "a.b.x.com", True),
        ("*.x.com", "x.com", False),  # apex excluded, mirrors the SC
        ("*.x.com", "*.a.x.com", True),
        ("*.a.x.com", "*.x.com", False),
        ("*.x.com", "*.x.com", True),
        ("*.x.com", "*", False),
        ("api.x.com", "*.x.com", False),
        ("api.x.com", "*", False),
        ("api.x.com", "other.x.com", False),
        ("*", "anything.example", True),
        ("*", "*", True),
    ],
)
def test_host_pattern_covers_matrix(secret_pattern, injection_host, covers) -> None:
    assert host_pattern_covers(secret_pattern, injection_host) is covers


def test_secret_hosts_cover_tolerates_malformed_entries() -> None:
    assert not secret_hosts_cover(None, "api.x.com")
    assert not secret_hosts_cover("api.x.com", "api.x.com")
    assert not secret_hosts_cover([None, 7], "api.x.com")
    assert secret_hosts_cover([None, "api.x.com"], "api.x.com")


def test_user_secret_references_extracts_and_tolerates_malformed() -> None:
    policy = {
        "secret_injections": [
            _user_injection(),
            {"id": "inline", "value_template": "Bearer ${secret}"},
            {"id": "bad-ref", "value_from": {"user_secret": 7}},
            "not-a-dict",
            {"id": "no-match", "value_from": {"user_secret": "gh-token"}},
        ]
    }

    references = user_secret_references(policy)

    assert references == [
        {
            "injection_id": "slack-token",
            "secret_name": "slack-user-token",
            "match_host": "api.slack.com",
            "match_scheme": "https",
        },
        {"injection_id": "no-match", "secret_name": "gh-token", "match_host": "", "match_scheme": ""},
    ]
    assert user_secret_references(None) == []
    assert user_secret_references({"secret_injections": "nope"}) == []


def test_expand_for_owner_hydrates_and_strips_value_from(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    events: list[tuple[str, str, str, str]] = []

    expanded = expand_policy_secret_values_for_owner(
        profile_id="profile-a",
        policy={"secret_injections": [_user_injection()]},
        secret_material={},
        owner_id="user-a",
        owner_secrets=_owner_secrets(),
        on_unresolved=lambda *args: events.append(args),
    )

    assert events == []
    assert "unfulfilled_secret_injections" not in expanded
    injection = expanded["secret_injections"][0]
    assert injection["value"] == "xoxp-alice"
    assert "value_from" not in injection
    assert injection["header"] == "authorization"


def test_expand_for_owner_wildcard_binding_covers_subdomains(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)

    expanded = expand_policy_secret_values_for_owner(
        profile_id="profile-a",
        policy={"secret_injections": [_user_injection(match={"scheme": "https", "host": "files.slack.com"})]},
        secret_material={},
        owner_id="user-a",
        owner_secrets=_owner_secrets(allowed_hosts=["*.slack.com"]),
    )

    assert expanded["secret_injections"][0]["value"] == "xoxp-alice"


@pytest.mark.parametrize(
    ("injection", "owner_secrets_kwargs", "reason", "outcome"),
    [
        # Grant unusable → fail-closed marker so the SC can block the destination
        # with a legible reason (the point of this feature).
        (_user_injection(value_from={"user_secret": "absent"}), {}, "missing", "unfulfilled"),
        (_user_injection(match=_full_match(host="evil.example.com")), {}, "host_binding", "unfulfilled"),
        (
            _user_injection(match=_full_match(host="slack.com")),
            {"allowed_hosts": ["*.slack.com"]},
            "host_binding",  # apex not covered by the wildcard binding
            "unfulfilled",
        ),
        (
            _user_injection(value_template="Bearer ${secret}" + "x" * 8192),
            {},
            "rendered_too_long",
            "unfulfilled",
        ),
        # Malformed definition → silently omitted (author-time-validated shapes;
        # a non-https marker would be inert anyway).
        (_user_injection(match={"scheme": "http", "host": "api.slack.com"}), {}, "scheme", "omitted"),
        (_user_injection(match={"host": "api.slack.com"}), {}, "scheme", "omitted"),
        (_user_injection(value_template="no placeholder"), {}, "invalid_template", "omitted"),
    ],
)
def test_expand_for_owner_unresolved_outcomes(monkeypatch, injection, owner_secrets_kwargs, reason, outcome) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    events: list[tuple[str, str, str, str]] = []

    expanded = expand_policy_secret_values_for_owner(
        profile_id="profile-a",
        policy={"secret_injections": [injection]},
        secret_material={},
        owner_id="user-a",
        owner_secrets=_owner_secrets(**owner_secrets_kwargs),
        on_unresolved=lambda *args: events.append(args),
    )

    # The credential is never injected, whatever the outcome.
    assert expanded["secret_injections"] == []
    assert len(events) == 1
    assert events[0][0] == reason
    assert events[0][1] == outcome
    assert events[0][2] == injection["id"]
    assert "xoxp-alice" not in "".join(events[0])

    markers = expanded.get("unfulfilled_secret_injections", [])
    if outcome == "unfulfilled":
        # Identifiers only — never a value or value_from on the wire.
        assert markers == [{"id": injection["id"], "match": injection["match"], "header": injection["header"]}]
        assert "value" not in markers[0] and "value_from" not in markers[0]
    else:
        assert markers == []


def test_expand_for_owner_marks_unfulfilled_on_undecryptable_material(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    events: list[tuple[str, str, str, str]] = []
    wrong_owner = _owner_secrets(user_id="user-b")

    expanded = expand_policy_secret_values_for_owner(
        profile_id="profile-a",
        policy={"secret_injections": [_user_injection()]},
        secret_material={},
        owner_id="user-a",
        owner_secrets=wrong_owner,
        on_unresolved=lambda *args: events.append(args),
    )

    assert expanded["secret_injections"] == []
    assert events == [("decrypt", "unfulfilled", "slack-token", "slack-user-token")]
    assert expanded["unfulfilled_secret_injections"] == [
        {"id": "slack-token", "match": _user_injection()["match"], "header": "authorization"}
    ]


def test_expand_without_owner_context_marks_unfulfilled(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)

    expanded = expand_profile_policy_secret_values(
        profile_id="profile-a",
        policy={"secret_injections": [_user_injection()]},
        secret_material={},
    )

    # No owner context → grant can't resolve → fail-closed marker, never a
    # value_from leak and never a silent uncredentialed passthrough.
    assert expanded["secret_injections"] == []
    assert expanded["unfulfilled_secret_injections"] == [
        {"id": "slack-token", "match": _user_injection()["match"], "header": "authorization"}
    ]


def test_expand_for_owner_never_emits_value_from_anywhere(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    inline_ciphertext = encrypt_profile_secret_value(
        profile_id="profile-a", injection_id="inline-key", value="inline-secret"
    )
    policy = {
        "secret_injections": [
            _user_injection(),
            _user_injection(id="unresolvable", value_from={"user_secret": "absent"}),
            {
                "id": "inline-key",
                "match": {"scheme": "https", "host": "api.anthropic.com"},
                "type": "request_header",
                "header": "x-api-key",
                "value_template": "${secret}",
            },
        ]
    }

    expanded = expand_policy_secret_values_for_owner(
        profile_id="profile-a",
        policy=policy,
        secret_material={"inline-key": inline_ciphertext},
        owner_id="user-a",
        owner_secrets=_owner_secrets(),
    )

    assert not _scan_for_key(expanded, "value_from")
    values = {injection["id"]: injection.get("value") for injection in expanded["secret_injections"]}
    assert values == {"slack-token": "xoxp-alice", "inline-key": "inline-secret"}


def test_split_collects_nothing_for_value_from_and_preserves_it() -> None:
    policy = {
        "secret_injections": [
            _user_injection(),
            _user_injection(id="second", value_from={"user_secret": "gh-token"}),
        ]
    }

    public_policy, values = split_profile_policy_secret_values(policy)

    assert values == {}
    assert [injection["value_from"] for injection in public_policy["secret_injections"]] == [
        {"user_secret": "slack-user-token"},
        {"user_secret": "gh-token"},
    ]
    assert redacted_profile_policy(policy) == public_policy
