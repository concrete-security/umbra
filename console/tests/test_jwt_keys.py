import base64
from datetime import datetime, timedelta, timezone
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from concrete_console.jwt_keys import JwtManager, JwtSettings


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def write_ed25519_keypair(tmp_path):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.jwks"
    private_path.write_bytes(private_pem)
    public_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": "test-key",
                        "alg": "EdDSA",
                        "x": b64url(public_bytes),
                    }
                ]
            }
        )
    )
    return private_path, public_path


def settings_for(tmp_path) -> JwtSettings:
    private_path, public_path = write_ed25519_keypair(tmp_path)
    return JwtSettings(
        algorithm="EdDSA",
        private_key_ref=f"file://{private_path}",
        public_keys_ref=f"file://{public_path}",
        active_kid="test-key",
        issuer="issuer",
        audience="audience",
        access_ttl_seconds=3600,
        leeway_seconds=0,
    )


def test_access_token_round_trips_with_configured_jwks(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))

    result = manager.issue_access_token(
        user_id="00000000-0000-4000-8000-000000000001",
        entity_id="00000000-0000-4000-8000-000000000002",
    )
    claims = manager.verify_access_token(result.access_token)

    assert claims["sub"] == "00000000-0000-4000-8000-000000000001"
    assert claims["entity_id"] == "00000000-0000-4000-8000-000000000002"
    assert claims["jti"] == str(result.jti)
    assert result.expires_at > datetime.now(timezone.utc)


def test_access_token_rejects_caller_supplied_key_headers(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))
    private_key = manager.private_key
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "issuer",
            "aud": "audience",
            "sub": "00000000-0000-4000-8000-000000000001",
            "entity_id": "00000000-0000-4000-8000-000000000002",
            "jti": "00000000-0000-4000-8000-000000000003",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(hours=1),
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key", "typ": "at+JWT", "jku": "https://attacker.example/jwks.json"},
    )

    with pytest.raises(jwt.InvalidTokenError, match="caller-supplied key headers"):
        manager.verify_access_token(token)
