from fastapi.testclient import TestClient

from concrete_console import app as app_module
from concrete_console.app import app


def test_healthz() -> None:
    response = TestClient(app).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "public, max-age=60"


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


def test_metrics_requires_bearer_token(monkeypatch) -> None:
    monkeypatch.setenv("METRICS_TOKEN", "metrics-token")

    response = TestClient(app).get("/metrics")

    assert response.status_code == 401


def test_metrics_exposes_prometheus_text(monkeypatch) -> None:
    monkeypatch.setenv("METRICS_TOKEN", "metrics-token")

    client = TestClient(app)
    client.get("/healthz")
    response = client.get("/metrics", headers={"Authorization": "Bearer metrics-token"})

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "concrete_console_requests_total" in response.text
    assert "concrete_console_request_duration_seconds" in response.text
