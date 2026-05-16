import base64
from datetime import datetime, timedelta, timezone
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from concrete_console.jwt_keys import JwtManager, JwtSettings


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_ed25519_material(kid: str):
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
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "x": b64url(public_bytes),
    }
    return private_pem, jwk


def generate_rsa_material(kid: str, *, key_size: int):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    return private_pem, jwk


def write_ed25519_keypair(tmp_path):
    private_pem, jwk = generate_ed25519_material("test-key")

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.jwks"
    private_path.write_bytes(private_pem)
    public_path.write_text(json.dumps({"keys": [jwk]}))
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


def access_claims(now: datetime):
    return {
        "iss": "issuer",
        "aud": "audience",
        "sub": "00000000-0000-4000-8000-000000000001",
        "entity_id": "00000000-0000-4000-8000-000000000002",
        "jti": "00000000-0000-4000-8000-000000000003",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
    }


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


def test_rs256_refuses_weak_rsa_key_at_startup(tmp_path) -> None:
    private_pem, jwk = generate_rsa_material("weak-key", key_size=1024)
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.jwks"
    private_path.write_bytes(private_pem)
    public_path.write_text(json.dumps({"keys": [jwk]}))

    settings = JwtSettings(
        algorithm="RS256",
        private_key_ref=f"file://{private_path}",
        public_keys_ref=f"file://{public_path}",
        active_kid="weak-key",
        issuer="issuer",
        audience="audience",
        access_ttl_seconds=3600,
        leeway_seconds=0,
    )

    with pytest.raises(ValueError, match="RS256 keys must be at least 2048 bits"):
        JwtManager(settings)


def test_rotate_switches_active_kid_and_retains_old_verifier(tmp_path) -> None:
    private_path, public_path = write_ed25519_keypair(tmp_path)
    manager = JwtManager(
        JwtSettings(
            algorithm="EdDSA",
            private_key_ref=f"file://{private_path}",
            public_keys_ref=f"file://{public_path}",
            active_kid="test-key",
            issuer="issuer",
            audience="audience",
            access_ttl_seconds=3600,
            leeway_seconds=0,
        )
    )
    old_token = manager.issue_access_token(
        user_id="00000000-0000-4000-8000-000000000001",
        entity_id="00000000-0000-4000-8000-000000000002",
    ).access_token
    next_private_pem, next_jwk = generate_ed25519_material("next-key")
    private_path.write_bytes(next_private_pem)
    public_path.write_text(json.dumps({"keys": [next_jwk]}))

    rotation = manager.rotate(new_kid="next-key", retire_old_after_seconds=3600)
    new_token = manager.issue_access_token(
        user_id="00000000-0000-4000-8000-000000000001",
        entity_id="00000000-0000-4000-8000-000000000002",
    ).access_token

    assert rotation.old_active_kid == "test-key"
    assert rotation.active_kid == "next-key"
    assert rotation.retiring_kids == ("test-key",)
    assert jwt.get_unverified_header(new_token)["kid"] == "next-key"
    assert manager.verify_access_token(old_token)["sub"] == "00000000-0000-4000-8000-000000000001"
    assert manager.verify_access_token(new_token)["sub"] == "00000000-0000-4000-8000-000000000001"


def test_rotate_with_immediate_retirement_rejects_old_kid(tmp_path) -> None:
    private_path, public_path = write_ed25519_keypair(tmp_path)
    manager = JwtManager(
        JwtSettings(
            algorithm="EdDSA",
            private_key_ref=f"file://{private_path}",
            public_keys_ref=f"file://{public_path}",
            active_kid="test-key",
            issuer="issuer",
            audience="audience",
            access_ttl_seconds=3600,
            leeway_seconds=0,
        )
    )
    old_token = manager.issue_access_token(
        user_id="00000000-0000-4000-8000-000000000001",
        entity_id="00000000-0000-4000-8000-000000000002",
    ).access_token
    next_private_pem, next_jwk = generate_ed25519_material("next-key")
    private_path.write_bytes(next_private_pem)
    public_path.write_text(json.dumps({"keys": [next_jwk]}))

    rotation = manager.rotate(new_kid="next-key", retire_old_after_seconds=0)

    assert rotation.retiring_kids == ()
    with pytest.raises(jwt.InvalidTokenError, match="unknown kid"):
        manager.verify_access_token(old_token)


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


def test_access_token_rejects_unexpected_header_fields(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        access_claims(now),
        manager.private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key", "typ": "at+JWT", "cty": "JWT"},
    )

    with pytest.raises(jwt.InvalidTokenError, match="unexpected token header"):
        manager.verify_access_token(token)


def test_access_token_rejects_non_base64url_segments(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))

    with pytest.raises(jwt.InvalidTokenError, match="invalid token shape"):
        manager.verify_access_token("abc.def*.ghi")


def test_access_token_rejects_non_object_header(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))
    token = f"{b64url(b'[]')}.{b64url(b'{}')}.{b64url(b'signature')}"

    with pytest.raises(jwt.InvalidTokenError, match="invalid token header"):
        manager.verify_access_token(token)


def test_access_token_rejects_unsupported_algorithm_before_kid_lookup(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))
    header = b64url(json.dumps({"alg": "none", "kid": "test-key", "typ": "at+JWT"}).encode())
    token = f"{header}.{b64url(b'{}')}.{b64url(b'signature')}"

    with pytest.raises(jwt.InvalidTokenError, match="unsupported algorithm"):
        manager.verify_access_token(token)


def test_access_token_requires_registered_claims(tmp_path) -> None:
    manager = JwtManager(settings_for(tmp_path))
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "issuer",
            "aud": "audience",
            "sub": "00000000-0000-4000-8000-000000000001",
            "entity_id": "00000000-0000-4000-8000-000000000002",
            "jti": "00000000-0000-4000-8000-000000000003",
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        manager.private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key", "typ": "at+JWT"},
    )

    with pytest.raises(jwt.MissingRequiredClaimError, match='"nbf"'):
        manager.verify_access_token(token)


@pytest.mark.parametrize(
    ("claim_name", "claim_value"),
    [
        ("email", "user@example.com"),
        ("permissions", ["USER_MANAGE"]),
        ("profiles", [{"id": "00000000-0000-4000-8000-000000000004", "name": "default"}]),
    ],
)
def test_access_token_rejects_forbidden_payload_claims(tmp_path, claim_name, claim_value) -> None:
    manager = JwtManager(settings_for(tmp_path))
    now = datetime.now(timezone.utc)
    claims = access_claims(now)
    claims[claim_name] = claim_value
    token = jwt.encode(
        claims,
        manager.private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key", "typ": "at+JWT"},
    )

    with pytest.raises(jwt.InvalidTokenError, match="forbidden access token claims"):
        manager.verify_access_token(token)
