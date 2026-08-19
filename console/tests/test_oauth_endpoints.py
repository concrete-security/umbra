import pytest

from umbra_console import oauth_endpoints
from umbra_console.oauth_endpoints import (
    TokenEndpointError,
    assert_token_url_egress_allowed,
    normalize_token_url,
    sanitize_provider_error_code,
)


def test_sanitize_provider_error_code_strips_to_allowlist() -> None:
    assert sanitize_provider_error_code("invalid_grant") == "invalid_grant"
    # Control chars, spaces, and other unsafe characters collapse to '_'.
    assert sanitize_provider_error_code("bad grant!\n<script>") == "bad_grant___script_"
    # Nested dict shapes.
    assert sanitize_provider_error_code({"error": "access_denied"}) == "access_denied"
    assert sanitize_provider_error_code({"message": "x" * 200}) == "x" * 64  # truncated
    # Empty / unknown shapes fall back.
    assert sanitize_provider_error_code("") == "provider_error"
    assert sanitize_provider_error_code(None) == "provider_error"
    assert sanitize_provider_error_code(12345) == "provider_error"


def test_normalize_token_url_accepts_allowlisted_https() -> None:
    assert normalize_token_url("https://auth.openai.com/oauth/token") == (
        "https://auth.openai.com/oauth/token"
    )
    assert normalize_token_url(" https://slack.com/api/oauth.v2.access ") == (
        "https://slack.com/api/oauth.v2.access"
    )


def test_normalize_token_url_rejects_non_https_and_fragments() -> None:
    with pytest.raises(TokenEndpointError):
        normalize_token_url("http://auth.openai.com/oauth/token")
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https://auth.openai.com/oauth/token#frag")
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https:///oauth/token")  # no host


def test_normalize_token_url_rejects_non_allowlisted_host() -> None:
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https://evil.example.com/oauth/token")
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https://169.254.169.254/latest/meta-data/")
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https://localhost/oauth/token")


def test_allowlist_is_env_overridable(monkeypatch) -> None:
    monkeypatch.setenv("OAUTH_TOKEN_URL_HOSTS", "id.example.com, notion.example.com")
    assert normalize_token_url("https://notion.example.com/token")
    with pytest.raises(TokenEndpointError):
        normalize_token_url("https://auth.openai.com/oauth/token")  # no longer allowed


def test_assert_egress_allowed_rejects_private_resolution(monkeypatch) -> None:
    # Host is on the allowlist but resolves to a private/link-local/loopback
    # address (DNS-rebinding or an internal-only name) -> reject.
    monkeypatch.setenv("OAUTH_TOKEN_URL_HOSTS", "rebind.example.com")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(2, 1, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(oauth_endpoints.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(TokenEndpointError):
        assert_token_url_egress_allowed("https://rebind.example.com/token")


def test_assert_egress_allowed_accepts_public_resolution(monkeypatch) -> None:
    monkeypatch.setenv("OAUTH_TOKEN_URL_HOSTS", "ok.example.com")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(oauth_endpoints.socket, "getaddrinfo", fake_getaddrinfo)
    assert_token_url_egress_allowed("https://ok.example.com/token")  # no raise


def test_assert_egress_allowed_rejects_various_private_ranges(monkeypatch) -> None:
    monkeypatch.setenv("OAUTH_TOKEN_URL_HOSTS", "h.example.com")
    for addr in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1", "fd00::1"):

        def fake_getaddrinfo(host, port, *args, _addr=addr, **kwargs):
            family = 10 if ":" in _addr else 2
            return [(family, 1, 6, "", (_addr, 443, 0, 0) if family == 10 else (_addr, 443))]

        monkeypatch.setattr(oauth_endpoints.socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(TokenEndpointError):
            assert_token_url_egress_allowed("https://h.example.com/token")
