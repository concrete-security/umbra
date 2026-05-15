import pytest
import jwt

from concrete_console.crypto import pkce_s256
from concrete_console.oidc import (
    IdpOAuthError,
    OidcSettings,
    google_authorize_redirect,
    oidc_settings,
    poll_device_code,
    verify_google_id_token,
)


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
    settings = OidcSettings(
        google_client_id="google-client",
        google_client_secret="secret",
        console_url="https://console.example.com",
        client_allowlist=frozenset({"concrete-cli-v1"}),
        authorize_url="https://accounts.example/authorize",
        token_url="https://accounts.example/token",
        device_code_url="https://accounts.example/device",
        jwks_url="https://accounts.example/jwks",
    )

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
    settings = OidcSettings(
        google_client_id="google-client",
        google_client_secret="secret",
        console_url="https://console.example.com",
        client_allowlist=frozenset({"concrete-cli-v1"}),
        authorize_url="https://accounts.example/authorize",
        token_url="https://accounts.example/token",
        device_code_url="https://accounts.example/device",
        jwks_url="https://accounts.example/jwks",
    )
    token = jwt.encode(
        {"sub": "subject", "email": "admin@example.com"},
        "unused-but-long-enough-for-hs256-tests",
        algorithm="HS256",
        headers={"jku": "https://attacker.example/jwks.json"},
    )

    with pytest.raises(jwt.InvalidTokenError, match="caller-supplied key headers"):
        import asyncio

        asyncio.run(verify_google_id_token(token, nonce=None, access_token=None, settings=settings))


def test_device_poll_preserves_idp_pending_error(monkeypatch) -> None:
    settings = OidcSettings(
        google_client_id="google-client",
        google_client_secret="secret",
        console_url="https://console.example.com",
        client_allowlist=frozenset({"concrete-cli-v1"}),
        authorize_url="https://accounts.example/authorize",
        token_url="https://accounts.example/token",
        device_code_url="https://accounts.example/device",
        jwks_url="https://accounts.example/jwks",
    )

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
