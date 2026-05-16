import asyncio
import hashlib
import json
from types import SimpleNamespace

from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from concrete_console import audit_anchor
from concrete_console import app as app_module
from concrete_console import readiness
from concrete_console import scheduler
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


def test_rate_limit_returns_retry_after(monkeypatch) -> None:
    app_module.clear_rate_limit_state()
    monkeypatch.setattr(app_module, "ANONYMOUS_IP_RPM", 2)
    try:
        client = TestClient(app)
        assert client.get("/healthz").status_code == 200
        assert client.get("/healthz").status_code == 200
        response = client.get("/healthz", headers={"X-Request-Id": "limited-request"})

        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"
        assert response.headers["x-request-id"] == "limited-request"
        assert response.json() == {
            "error": {
                "code": "RATE_LIMITED",
                "message": "rate limit exceeded",
                "details": {"retry_after_seconds": 60, "limit": "ip"},
                "request_id": "limited-request",
            }
        }
    finally:
        app_module.clear_rate_limit_state()


def test_api_body_limit_rejects_before_route_parsing(monkeypatch) -> None:
    app_module.clear_rate_limit_state()
    monkeypatch.setattr(app_module, "API_BODY_LIMIT_BYTES", 8)

    response = TestClient(app).post(
        "/api/v1/auth/token",
        content=b"x" * 9,
        headers={"X-Request-Id": "large-request"},
    )

    assert response.status_code == 413
    assert response.headers["x-request-id"] == "large-request"
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert response.json()["error"]["details"] == {"limit_bytes": 8}


def test_json_body_requires_application_json_content_type() -> None:
    app_module.clear_rate_limit_state()

    response = TestClient(app).post(
        "/api/v1/auth/token",
        content=b"{}",
        headers={"Content-Type": "text/plain", "X-Request-Id": "bad-media"},
    )

    assert response.status_code == 415
    assert response.headers["x-request-id"] == "bad-media"
    assert response.json() == {
        "error": {
            "code": "UNSUPPORTED_MEDIA_TYPE",
            "message": "Content-Type must be application/json",
            "details": {},
            "request_id": "bad-media",
        }
    }


def test_bodyless_api_request_does_not_require_content_type() -> None:
    app_module.clear_rate_limit_state()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={},
        method="POST",
        url=SimpleNamespace(path="/api/v1/auth/token"),
    )

    response = asyncio.run(app_module.request_guard_response(request, "bodyless-request"))

    assert response is None


def test_validation_errors_use_error_envelope() -> None:
    request = SimpleNamespace(state=SimpleNamespace(request_id="validation-request"))
    exc = RequestValidationError(
        [
            {
                "loc": ("body", "grant_type"),
                "msg": "Field required",
                "type": "missing",
            }
        ]
    )

    response = asyncio.run(app_module.validation_exception_handler(request, exc))
    body = json.loads(response.body)

    assert response.status_code == 422
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["message"] == "request validation failed"
    assert body["error"]["request_id"] == "validation-request"
    assert body["error"]["details"]["errors"] == [
        {
            "loc": ["body", "grant_type"],
            "msg": "Field required",
            "type": "missing",
        }
    ]


def test_forwarded_client_ip_prefers_leftmost_public(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_FORWARDED_HEADERS", "true")
    app_module.clear_rate_limit_state()
    request = SimpleNamespace(
        client=SimpleNamespace(host="10.0.0.5"),
        headers={"x-forwarded-for": "10.0.0.1, 8.8.8.8, 1.1.1.1"},
    )

    assert app_module.resolved_client_ip(request) == "8.8.8.8"


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
    monkeypatch.setattr(readiness, "_check_phala_adapter", ok)
    monkeypatch.setattr(readiness, "_check_audit_anchor_target", ok)
    monkeypatch.setattr(readiness, "_check_operation_scheduler", ok)

    assert asyncio.run(readiness.run_ready_checks()) == {
        "audit_anchor_target": "ok",
        "cloudflare_adapter": "ok",
        "database": "ok",
        "jwt_keys": "ok",
        "oidc_jwks": "ok",
        "operation_scheduler": "ok",
        "phala_adapter": "ok",
    }


def test_lifespan_verifies_phala_cli_integrity_and_runs_scheduler(monkeypatch) -> None:
    seen: list[float] = []
    scheduler_tasks: list[object] = []

    async def verify(*, fetch_timeout: float) -> None:
        seen.append(fetch_timeout)

    def start() -> object:
        task = object()
        scheduler_tasks.append(task)
        return task

    async def stop(task: object) -> None:
        scheduler_tasks.append(task)

    async def close() -> None:
        return None

    monkeypatch.setattr(app_module, "verify_configured_phala_cli", verify)
    monkeypatch.setattr(app_module, "start_operation_scheduler", start)
    monkeypatch.setattr(app_module, "stop_operation_scheduler", stop)
    monkeypatch.setattr(app_module, "close_pool", close)

    async def exercise() -> None:
        async with app_module.lifespan(app):
            return None

    asyncio.run(exercise())

    assert seen == [5.0]
    assert len(scheduler_tasks) == 2
    assert scheduler_tasks[0] is scheduler_tasks[1]


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


def test_phala_package_version_reads_installed_package_json(tmp_path) -> None:
    package_dir = tmp_path / "node_modules" / "phala"
    bin_dir = package_dir / "dist"
    bin_dir.mkdir(parents=True)
    cli = bin_dir / "index.js"
    cli.write_text("#!/usr/bin/env node\n")
    (package_dir / "package.json").write_text('{"name":"phala","version":"1.1.18"}')
    launcher = tmp_path / "bin" / "phala"
    launcher.parent.mkdir()
    launcher.symlink_to(cli)

    assert readiness.phala_package_version(str(launcher)) == "1.1.18"


def test_phala_readiness_verifies_tarball_digest(monkeypatch) -> None:
    tarball = b"phala-tarball"
    expected = hashlib.sha256(tarball).hexdigest()
    seen: list[str] = []

    monkeypatch.setenv("PHALA_API_TOKEN", "phala-token")
    monkeypatch.setenv("PHALA_CLI_SHA256", expected)
    monkeypatch.setenv("PHALA_CLI_PATH", "/usr/local/bin/phala")
    monkeypatch.setattr(readiness, "phala_package_version", lambda path: "1.1.18")
    monkeypatch.setattr(readiness, "phala_tarball_url", lambda version: "https://registry.example/phala.tgz")

    class FakeClient:
        def __init__(self, *, timeout: float, follow_redirects: bool) -> None:
            assert timeout == 0.5
            assert follow_redirects is True

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url: str):
            seen.append(url)

            def raise_for_status() -> None:
                return None

            return SimpleNamespace(content=tarball, raise_for_status=raise_for_status)

    monkeypatch.setattr(readiness.httpx, "AsyncClient", FakeClient)

    asyncio.run(readiness._check_phala_adapter())

    assert seen == ["https://registry.example/phala.tgz"]


def test_phala_readiness_skips_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("PHALA_API_TOKEN", raising=False)
    monkeypatch.delenv("PHALA_CLI_SHA256", raising=False)

    asyncio.run(readiness._check_phala_adapter())


def test_audit_anchor_readiness_probes_configured_postgres_target(monkeypatch) -> None:
    seen: list[tuple[str, float | None]] = []
    queries: list[str] = []

    monkeypatch.setenv(
        "AUDIT_ANCHOR_TARGET",
        "postgresql://anchor:secret@anchor-db:5432/audit?sslmode=require&table=anchors",
    )

    class FakeConn:
        async def execute(self, query: str) -> None:
            queries.append(query)

        async def close(self) -> None:
            return None

    async def connect(dsn: str, *, timeout: float | None = None):
        seen.append((dsn, timeout))
        return FakeConn()

    monkeypatch.setattr(audit_anchor.asyncpg, "connect", connect)

    asyncio.run(readiness._check_audit_anchor_target())

    assert seen == [("postgresql://anchor:secret@anchor-db:5432/audit?sslmode=require", 0.5)]
    assert queries == ['SELECT 1 FROM "anchors" LIMIT 0']


def test_audit_anchor_readiness_skips_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("AUDIT_ANCHOR_TARGET", raising=False)

    asyncio.run(readiness._check_audit_anchor_target())


def test_operation_scheduler_readiness_requires_recent_tick(monkeypatch) -> None:
    monkeypatch.setenv("RECONCILER_INTERVAL_SECONDS", "30")
    scheduler._last_successful_tick_monotonic = None

    try:
        scheduler.check_operation_scheduler_recent(now=100)
    except RuntimeError as exc:
        assert str(exc) == "operation scheduler has not ticked"
    else:
        raise AssertionError("expected missing scheduler tick failure")

    scheduler.mark_scheduler_tick_success(now=100)
    scheduler.check_operation_scheduler_recent(now=159)

    try:
        scheduler.check_operation_scheduler_recent(now=161)
    except RuntimeError as exc:
        assert str(exc) == "operation scheduler tick is stale"
    else:
        raise AssertionError("expected stale scheduler tick failure")


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
