import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient

from concrete_console import app as app_module
from concrete_console import readiness
from concrete_console.app import app


def test_healthz() -> None:
    response = TestClient(app).get("/healthz", headers={"X-Request-Id": "test-request"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-request-id"] == "test-request"
    assert response.headers["cache-control"] == "public, max-age=60"
    assert response.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"


def test_invalid_request_id_is_replaced() -> None:
    response = TestClient(app).get("/healthz", headers={"X-Request-Id": "bad request id"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] != "bad request id"


def test_readyz_renders_checks(monkeypatch) -> None:
    async def fake_checks():
        return {"database": "ok", "jwt_keys": "ok"}

    monkeypatch.setattr(app_module, "run_ready_checks", fake_checks)

    response = TestClient(app).get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"checks": {"database": "ok", "jwt_keys": "ok"}}
    assert response.headers["cache-control"] == "public, max-age=60"


def test_readyz_returns_503_when_a_check_fails(monkeypatch) -> None:
    async def fake_checks():
        return {"database": "ok", "jwt_keys": "failed"}

    monkeypatch.setattr(app_module, "run_ready_checks", fake_checks)

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"checks": {"database": "ok", "jwt_keys": "failed"}}


def test_run_ready_checks_includes_oidc_jwks(monkeypatch) -> None:
    async def ok() -> None:
        return None

    monkeypatch.setattr(readiness, "_check_database", ok)
    monkeypatch.setattr(readiness, "_check_jwt_keys", ok)
    monkeypatch.setattr(readiness, "_check_oidc_jwks", ok)
    monkeypatch.setattr(readiness, "_check_cloudflare_adapter", ok)

    assert asyncio.run(readiness.run_ready_checks()) == {
        "cloudflare_adapter": "ok",
        "database": "ok",
        "jwt_keys": "ok",
        "oidc_jwks": "ok",
    }


def test_oidc_jwks_readiness_requires_keys(monkeypatch) -> None:
    async def no_keys(*, force: bool) -> dict:
        assert force is False
        return {}

    monkeypatch.setattr(readiness, "load_google_jwks", no_keys)

    try:
        asyncio.run(readiness._check_oidc_jwks())
    except RuntimeError as exc:
        assert str(exc) == "OIDC JWKS did not return any keys"
    else:
        raise AssertionError("expected OIDC JWKS readiness failure")


def test_cloudflare_readiness_probes_configured_zones(monkeypatch) -> None:
    seen: list[tuple[str, str]] = []

    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "dev-zone")
    monkeypatch.setenv("SECURITY_CVM_ZONE_ID", "security-zone")

    class FakeClient:
        def __init__(self, *, timeout: float) -> None:
            assert timeout == 0.5

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url: str, *, headers: dict[str, str]):
            seen.append((url, headers["Authorization"]))
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(readiness.httpx, "AsyncClient", FakeClient)

    asyncio.run(readiness._check_cloudflare_adapter())

    assert set(seen) == {
        ("https://api.cloudflare.com/client/v4/zones/dev-zone", "Bearer cf-token"),
        ("https://api.cloudflare.com/client/v4/zones/security-zone", "Bearer cf-token"),
    }


def test_cloudflare_readiness_skips_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ZONE_ID", raising=False)
    monkeypatch.delenv("SECURITY_CVM_ZONE_ID", raising=False)

    asyncio.run(readiness._check_cloudflare_adapter())


def test_metrics_requires_bearer_token(monkeypatch) -> None:
    monkeypatch.setenv("METRICS_TOKEN", "metrics-token")

    response = TestClient(app).get("/metrics", headers={"X-Request-Id": "metrics-request"})

    assert response.status_code == 401
    assert response.json()["error"]["request_id"] == "metrics-request"
    assert response.headers["cache-control"] == "no-store"


def test_metrics_exposes_prometheus_text(monkeypatch) -> None:
    monkeypatch.setenv("METRICS_TOKEN", "metrics-token")

    client = TestClient(app)
    client.get("/healthz")
    response = client.get("/metrics", headers={"Authorization": "Bearer metrics-token"})

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "concrete_console_requests_total" in response.text
    assert "concrete_console_request_duration_seconds" in response.text
