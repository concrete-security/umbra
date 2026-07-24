from datetime import datetime, timedelta, timezone
import json

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from concrete_console.crypto import pkce_s256
from concrete_console.oidc import (
    IdpOAuthError,
    OidcSettings,
    _at_hash,
    exchange_authorization_code,
    google_authorize_redirect,
    oidc_settings,
    poll_device_code,
    start_device_flow,
    verify_google_id_token,
)


GOOGLE_TEST_KID = "a" * 40


def oidc_test_settings() -> OidcSettings:
    return OidcSettings(
        google_client_id="google-client",
        google_client_secret="secret",
        google_device_client_id="google-device-client",
        google_device_client_secret="device-secret",
        console_url="https://console.example.com",
        client_allowlist=frozenset({"concrete-cli-v1"}),
        authorize_url="https://accounts.example/authorize",
        token_url="https://accounts.example/token",
        device_code_url="https://accounts.example/device",
        jwks_url="https://accounts.example/jwks",
    )


def signed_google_token(*, claims_override: dict | None = None) -> tuple[str, dict[str, dict]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = GOOGLE_TEST_KID
    public_jwk["alg"] = "RS256"
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "google-client",
        "sub": "subject",
        "email": "admin@example.com",
        "email_verified": True,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(claims_override or {})
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": GOOGLE_TEST_KID, "typ": "JWT"})
    return token, {GOOGLE_TEST_KID: public_jwk}


def signed_google_token_with_headers(
    *, headers_override: dict[str, str], claims_override: dict | None = None
) -> tuple[str, dict[str, dict]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = GOOGLE_TEST_KID
    public_jwk["alg"] = "RS256"
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "google-client",
        "sub": "subject",
        "email": "admin@example.com",
        "email_verified": True,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(claims_override or {})
    headers = {"kid": GOOGLE_TEST_KID, "typ": "JWT"}
    headers.update(headers_override)
    token = jwt.encode(claims, private_key, algorithm="RS256", headers=headers)
    return token, {GOOGLE_TEST_KID: public_jwk}


def install_jwks(monkeypatch, jwks):
    async def fake_load_google_jwks(*, settings=None, force=False):
        return jwks

    monkeypatch.setattr("concrete_console.oidc.load_google_jwks", fake_load_google_jwks)


class RecordingResponse:
    def __init__(self, *, status_code: int = 200, body: dict | None = None) -> None:
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self) -> dict:
        return self._body

    def raise_for_status(self) -> None:
        return None


def recording_client(captured: list[dict], *, response: RecordingResponse):
    """httpx.AsyncClient stand-in recording each POST's url + form data."""

    class _RecordingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, url, *args, **kwargs) -> RecordingResponse:
            captured.append({"url": url, "data": kwargs.get("data")})
            return response

    return _RecordingClient


def test_oidc_settings_refuses_endpoint_override_without_debug_flag(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_ID", "google-client")
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ALLOWLIST", "concrete-cli-v1")
    monkeypatch.setenv("GOOGLE_TOKEN_URL", "https://idp.invalid/token")
    monkeypatch.setenv("OIDC_OVERRIDES_ALLOWED", "false")

    with pytest.raises(ValueError, match="GOOGLE_TOKEN_URL override"):
        oidc_settings()


def test_google_authorize_redirect_uses_console_callback_and_nonce() -> None:
    settings = oidc_test_settings()

    redirect = google_authorize_redirect(idp_state="state-value", nonce="nonce-value", settings=settings)

    assert redirect.startswith("https://accounts.example/authorize?")
    assert "client_id=google-client" in redirect
    assert "redirect_uri=https%3A%2F%2Fconsole.example.com%2Fapi%2Fv1%2Fauth%2Foidc%2Fcallback" in redirect
    assert "state=state-value" in redirect
    assert "nonce=nonce-value" in redirect


def test_pkce_s256_matches_rfc7636_example() -> None:
    assert (
        pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_google_id_token_rejects_caller_supplied_key_headers_before_jwks(monkeypatch) -> None:
    settings = oidc_test_settings()
    token = jwt.encode(
        {"sub": "subject", "email": "admin@example.com"},
        "unused-but-long-enough-for-hs256-tests",
        algorithm="HS256",
        headers={"jku": "https://attacker.example/jwks.json"},
    )

    with pytest.raises(jwt.InvalidTokenError, match="caller-supplied key headers"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token=None, settings=settings))


def test_google_id_token_rejects_non_base64url_segments_before_jwks(monkeypatch) -> None:
    settings = oidc_test_settings()

    async def fail_load_google_jwks(*, settings=None, force=False):
        raise AssertionError("invalid token shape should fail before JWKS lookup")

    monkeypatch.setattr("concrete_console.oidc.load_google_jwks", fail_load_google_jwks)

    with pytest.raises(jwt.InvalidTokenError, match="invalid token shape"):
        import asyncio

        asyncio.run(verify_google_id_token("abc.def*.ghi", nonce=None, access_token=None, settings=settings))


@pytest.mark.parametrize("token_type", ["at+JWT", "JWS"])
def test_google_id_token_rejects_wrong_token_type(monkeypatch, token_type) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token_with_headers(headers_override={"typ": token_type})
    install_jwks(monkeypatch, jwks)

    with pytest.raises(jwt.InvalidTokenError, match="wrong token type"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token=None, settings=settings))


@pytest.mark.parametrize("email", ["", "   ", 123])
def test_google_id_token_requires_string_email(monkeypatch, email) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token(claims_override={"email": email})
    install_jwks(monkeypatch, jwks)

    with pytest.raises(jwt.InvalidTokenError, match="invalid email"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token=None, settings=settings))


def test_google_id_token_requires_azp_for_audience_array(monkeypatch) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token(claims_override={"aud": ["google-client"]})
    install_jwks(monkeypatch, jwks)

    with pytest.raises(jwt.InvalidTokenError, match="authorized party"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token=None, settings=settings))


def test_google_id_token_requires_at_hash_when_access_token_is_returned(monkeypatch) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token()
    install_jwks(monkeypatch, jwks)

    with pytest.raises(jwt.InvalidTokenError, match="at_hash"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token="access-token", settings=settings))


def test_google_id_token_accepts_matching_at_hash(monkeypatch) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token(claims_override={"at_hash": _at_hash("access-token")})
    install_jwks(monkeypatch, jwks)

    import asyncio

    claims = asyncio.run(verify_google_id_token(token, nonce=None, access_token="access-token", settings=settings))

    assert claims["sub"] == "subject"


def test_device_poll_preserves_idp_pending_error(monkeypatch) -> None:
    settings = oidc_test_settings()

    class FakeResponse:
        status_code = 400

        def json(self):
            return {"error": "authorization_pending"}

        def raise_for_status(self):
            raise AssertionError("poll_device_code should surface OAuth errors directly")

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("concrete_console.oidc.httpx.AsyncClient", FakeClient)

    with pytest.raises(IdpOAuthError) as exc:
        import asyncio

        asyncio.run(poll_device_code("device-code", settings=settings))

    assert exc.value.error == "authorization_pending"


@pytest.mark.parametrize(
    ("device_id", "device_secret", "expected_id", "expected_secret"),
    [
        ("device-id", "device-secret", "device-id", "device-secret"),
        (None, None, "web-id", "web-secret"),
    ],
    ids=["device_set", "device_unset_falls_back"],
)
def test_oidc_settings_resolves_device_client(
    monkeypatch, device_id, device_secret, expected_id, expected_secret
) -> None:
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_ID", "web-id")
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_SECRET", "web-secret")
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ALLOWLIST", "concrete-cli-v1")
    monkeypatch.delenv("GOOGLE_OIDC_DEVICE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OIDC_DEVICE_CLIENT_SECRET", raising=False)
    for override in ("GOOGLE_TOKEN_URL", "GOOGLE_DEVICE_CODE_URL", "GOOGLE_JWKS_URL"):
        monkeypatch.delenv(override, raising=False)
    if device_id is not None:
        monkeypatch.setenv("GOOGLE_OIDC_DEVICE_CLIENT_ID", device_id)
    if device_secret is not None:
        monkeypatch.setenv("GOOGLE_OIDC_DEVICE_CLIENT_SECRET", device_secret)

    settings = oidc_settings()

    assert settings.google_client_id == "web-id"
    assert settings.google_device_client_id == expected_id
    assert settings.google_device_client_secret == expected_secret


def test_start_device_flow_uses_device_client(monkeypatch) -> None:
    settings = oidc_test_settings()
    captured: list[dict] = []
    monkeypatch.setattr(
        "concrete_console.oidc.httpx.AsyncClient",
        recording_client(captured, response=RecordingResponse(body={"device_code": "dc"})),
    )

    import asyncio

    result = asyncio.run(start_device_flow(settings=settings))

    assert result == {"device_code": "dc"}
    assert captured[-1]["url"] == settings.device_code_url
    assert captured[-1]["data"]["client_id"] == "google-device-client"


def test_poll_device_code_uses_device_client(monkeypatch) -> None:
    settings = oidc_test_settings()
    captured: list[dict] = []
    monkeypatch.setattr(
        "concrete_console.oidc.httpx.AsyncClient",
        recording_client(captured, response=RecordingResponse(body={"id_token": "tok", "access_token": "at"})),
    )

    import asyncio

    result = asyncio.run(poll_device_code("device-code", settings=settings))

    assert result.id_token == "tok"
    assert captured[-1]["url"] == settings.token_url
    assert captured[-1]["data"]["client_id"] == "google-device-client"
    assert captured[-1]["data"]["client_secret"] == "device-secret"


def test_exchange_authorization_code_uses_web_client(monkeypatch) -> None:
    settings = oidc_test_settings()
    captured: list[dict] = []
    monkeypatch.setattr(
        "concrete_console.oidc.httpx.AsyncClient",
        recording_client(captured, response=RecordingResponse(body={"id_token": "tok"})),
    )

    import asyncio

    asyncio.run(exchange_authorization_code("auth-code", settings=settings))

    assert captured[-1]["url"] == settings.token_url
    assert captured[-1]["data"]["client_id"] == "google-client"
    assert captured[-1]["data"]["client_secret"] == "secret"


def test_verify_google_id_token_accepts_device_client_audience(monkeypatch) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token(claims_override={"aud": "google-device-client"})
    install_jwks(monkeypatch, jwks)

    import asyncio

    claims = asyncio.run(
        verify_google_id_token(
            token,
            nonce=None,
            access_token=None,
            audience=settings.google_device_client_id,
            settings=settings,
        )
    )

    assert claims["sub"] == "subject"


def test_verify_google_id_token_rejects_cross_client_audience(monkeypatch) -> None:
    settings = oidc_test_settings()
    token, jwks = signed_google_token()  # aud == "google-client"
    install_jwks(monkeypatch, jwks)

    with pytest.raises(jwt.InvalidTokenError, match="udience"):
        import asyncio

        asyncio.run(
            verify_google_id_token(
                token,
                nonce=None,
                access_token=None,
                audience=settings.google_device_client_id,
                settings=settings,
            )
        )
