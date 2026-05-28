import pytest
from cryptography.exceptions import InvalidTag

from concrete_console.profile_secrets import (
    decrypt_profile_secret_value,
    encrypt_profile_secret_value,
    expand_profile_policy_secret_values,
    split_profile_policy_secret_values,
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
