from contextlib import asynccontextmanager
import asyncio
from collections import deque
import hashlib
import hmac
import math
import re
from pathlib import Path
from typing import Annotated, AsyncIterator
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from concrete_console.audit_anchor import publish_audit_anchor_now
from concrete_console.config import load_settings
from concrete_console.db import close_pool
from concrete_console.log_config import bind_request_context, clear_context, configure_logging, logger
from concrete_console.metrics import monotonic_seconds, observe_request, prometheus_text
from concrete_console.readiness import run_ready_checks, verify_configured_phala_cli
from concrete_console.request_context import resolved_client_ip
from concrete_console.routes_auth import router as auth_router
from concrete_console.routes_internal import router as internal_router
from concrete_console.routes import router
from concrete_console.routes_admin import router as admin_router
from concrete_console.scheduler import start_operation_scheduler, stop_operation_scheduler

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
UUID_PATH_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
CANONICAL_UUID_PATH_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
RATE_LIMIT_WINDOW_SECONDS = 60.0
ANONYMOUS_IP_RPM = 60
AUTHENTICATED_IP_RPM = 600
CREDENTIAL_RPM = 1200
ROUTE_CREDENTIAL_RPM = 1200
AUTH_AUTHORIZE_IP_RPM = 30
AUTH_CALLBACK_IP_RPM = 30
AUTH_TOKEN_IP_RPM = 60
AUTH_DEVICE_IP_RPM = 30
AUTH_REFRESH_IP_RPM = 60
METRICS_IP_RPM = 60
AUDIT_EVENTS_CREDENTIAL_RPM = 60
TRAFFIC_LOGS_READ_CREDENTIAL_RPM = 30
ADMIN_RECONCILE_CREDENTIAL_RPM = 6
ADMIN_OVERVIEW_CREDENTIAL_RPM = 30
ADMIN_LOGS_STREAM_CREDENTIAL_RPM = 6
ADMIN_READ_CREDENTIAL_RPM = 120
POLICY_BUNDLE_CVM_RPM = 30
CVM_PROFILE_MUTATION_RPM = 12
TRAFFIC_LOG_INGEST_PRINCIPAL_RPM = 120
SC_CONTROL_RPM = 60
DEV_CONTROL_POLICY_RPM = 30
API_BODY_LIMIT_BYTES = 1024 * 1024
TRAFFIC_LOG_BODY_LIMIT_BYTES = 4 * 1024 * 1024
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}
ADMIN_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "frame-ancestors 'none'; base-uri 'self'"
)


def _admin_static_dir() -> Path:
    for candidate in (
        Path("/app/static/admin"),
        Path(__file__).resolve().parents[2] / "static" / "admin",
    ):
        if candidate.is_dir():
            return candidate
    return Path("/app/static/admin")


configure_logging()
log = logger()
RateLimitKey = tuple[str, str]
_rate_limit_lock = asyncio.Lock()
_rate_limit_events: dict[RateLimitKey, deque[float]] = {}


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await verify_configured_phala_cli(fetch_timeout=5.0)
    scheduler_task = start_operation_scheduler()
    try:
        yield
    finally:
        await stop_operation_scheduler(scheduler_task)
        try:
            await publish_audit_anchor_now()
        except Exception as exc:  # noqa: BLE001
            log.error("audit_anchor_shutdown_publish_failed", error_type=type(exc).__name__)
        await close_pool()


app = FastAPI(title="Concrete Console", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(internal_router)
app.include_router(router)
app.include_router(admin_router)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = resolve_request_id(request)
    request.state.request_id = request_id
    bind_request_context(request_id=request_id)
    started = monotonic_seconds()
    status = 500
    try:
        early_response = await request_guard_response(request, request_id)
        if early_response is not None:
            status = early_response.status_code
            apply_response_headers(request, early_response, request_id)
            return early_response
        response = await call_next(request)
        status = response.status_code
        apply_response_headers(request, response, request_id)
        return response
    finally:
        route = request.scope.get("route")
        route_label = getattr(route, "path", request.url.path)
        duration_seconds = monotonic_seconds() - started
        observe_request(
            route=route_label,
            method=request.method,
            status=status,
            duration_seconds=duration_seconds,
        )
        log.info(
            "request_completed",
            route=route_label,
            method=request.method,
            status=status,
            duration_ms=round(duration_seconds * 1000, 3),
        )
        clear_context()


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        detail = exc.detail.copy()
        detail["error"] = {**detail["error"], "request_id": request_id}
        return JSONResponse(status_code=exc.status_code, content=detail, headers=exc.headers)
    code = http_status_error_code(exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": str(exc.detail),
                "details": {},
                "request_id": request_id,
            }
        },
        headers=exc.headers,
    )


def http_status_error_code(status_code: int) -> str:
    return {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        412: "PRECONDITION_FAILED",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "VALIDATION_ERROR",
        428: "PRECONDITION_REQUIRED",
        429: "RATE_LIMITED",
        500: "INTERNAL",
        502: "UPSTREAM_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }.get(status_code, "INTERNAL" if status_code >= 500 else "BAD_REQUEST")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    if any(error.get("type") == "json_invalid" for error in exc.errors()):
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "BAD_REQUEST",
                    "message": "malformed JSON request body",
                    "details": {},
                    "request_id": request_id,
                }
            },
        )
    errors = [
        {
            "loc": list(error.get("loc", [])),
            "msg": str(error.get("msg", "validation error")),
            "type": str(error.get("type", "value_error")),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "request validation failed",
                "details": {"errors": errors},
                "request_id": request_id,
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled_exception", error_type=type(exc).__name__)
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL",
                "message": "internal server error",
                "details": {},
                "request_id": request_id,
            }
        },
    )


def resolve_request_id(request: Request) -> str:
    supplied = request.headers.get("x-request-id")
    if supplied and REQUEST_ID_RE.fullmatch(supplied):
        return supplied
    return str(uuid4())


async def request_guard_response(request: Request, request_id: str) -> JSONResponse | None:
    if is_cors_preflight(request):
        return error_response(
            403,
            "FORBIDDEN",
            "CORS preflight requests are not accepted",
            {"required": "cors_disabled"},
            request_id,
        )

    if has_noncanonical_uuid_path_segment(request.url.path):
        return error_response(
            400,
            "BAD_REQUEST",
            "path UUIDs must use canonical lowercase form",
            {},
            request_id,
        )

    body_limit = request_body_limit(request.url.path)
    if body_limit is not None:
        raw_length = request.headers.get("content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                content_length = 0
            if content_length > body_limit:
                return error_response(
                    413,
                    "PAYLOAD_TOO_LARGE",
                    "request body is too large",
                    {"limit_bytes": body_limit},
                    request_id,
                )
        if request_has_body(request) and not has_json_content_type(request):
            return error_response(
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json",
                {},
                request_id,
            )

    if path_exempt_from_rate_limit(request.url.path):
        rate_limited = None
    else:
        rate_limited = await check_rate_limit(request)
    if rate_limited is None:
        return None
    retry_after_seconds, limit_name = rate_limited
    return error_response(
        429,
        "RATE_LIMITED",
        "rate limit exceeded",
        {"retry_after_seconds": retry_after_seconds, "limit": limit_name},
        request_id,
        headers={"Retry-After": str(retry_after_seconds)},
    )


def is_cors_preflight(request: Request) -> bool:
    return (
        request.method == "OPTIONS"
        and "origin" in request.headers
        and "access-control-request-method" in request.headers
    )


def has_noncanonical_uuid_path_segment(path: str) -> bool:
    return any(
        UUID_PATH_SEGMENT_RE.fullmatch(segment)
        and CANONICAL_UUID_PATH_SEGMENT_RE.fullmatch(segment) is None
        for segment in path.split("/")
    )


def request_body_limit(path: str) -> int | None:
    if path == "/internal/traffic-logs":
        return TRAFFIC_LOG_BODY_LIMIT_BYTES
    if path.startswith("/api/v1/"):
        return API_BODY_LIMIT_BYTES
    return None


def request_has_body(request: Request) -> bool:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            return int(content_length) > 0
        except ValueError:
            return True
    return "transfer-encoding" in request.headers


def has_json_content_type(request: Request) -> bool:
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json"


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict,
    request_id: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details,
                "request_id": request_id,
            }
        },
        headers=headers,
    )


async def check_rate_limit(request: Request) -> tuple[int, str] | None:
    dimensions = rate_limit_dimensions(request)
    if not dimensions:
        return None
    now = monotonic_seconds()
    async with _rate_limit_lock:
        for key, budget, limit_name in dimensions:
            events = _rate_limit_events.setdefault(key, deque())
            prune_rate_limit_events(events, now)
            if len(events) >= budget:
                retry_after = max(1, math.ceil(RATE_LIMIT_WINDOW_SECONDS - (now - events[0])))
                return retry_after, limit_name
        for key, _, _ in dimensions:
            _rate_limit_events[key].append(now)
    return None


def rate_limit_dimensions(request: Request) -> list[tuple[RateLimitKey, int, str]]:
    ip_key = resolved_client_ip(request)
    credential = credential_fingerprint(request)
    route_key = f"{request.method} {request.url.path}"
    ip_scope = "auth" if credential else "anon"
    dimensions: list[tuple[RateLimitKey, int, str]] = [
        (
            ("ip", f"{ip_scope}:{ip_key}"),
            AUTHENTICATED_IP_RPM if credential else ANONYMOUS_IP_RPM,
            "ip",
        ),
    ]
    route_ip_budget_value = route_ip_budget(request.method, request.url.path)
    if route_ip_budget_value is not None:
        dimensions.append(
            (
                ("route_ip", f"{route_key}:{ip_key}"),
                route_ip_budget_value,
                "route_ip",
            )
        )
    if credential is not None:
        dimensions.append((("credential", credential), CREDENTIAL_RPM, "credential"))
        route_credential_key, route_credential_budget_value = route_credential_dimension(
            request.method,
            request.url.path,
        )
        dimensions.append(
            (
                ("route_credential", f"{route_credential_key}:{credential}"),
                route_credential_budget_value,
                "route_credential",
            )
        )
    return dimensions


def route_ip_budget(method: str, path: str) -> int | None:
    if method == "GET" and path == "/api/v1/auth/authorize":
        return AUTH_AUTHORIZE_IP_RPM
    if method == "GET" and path == "/api/v1/auth/oidc/callback":
        return AUTH_CALLBACK_IP_RPM
    if method == "POST" and path == "/api/v1/auth/token":
        return AUTH_TOKEN_IP_RPM
    if method == "POST" and path in {"/api/v1/auth/device/start", "/api/v1/auth/device/poll"}:
        return AUTH_DEVICE_IP_RPM
    if method == "POST" and path == "/api/v1/auth/refresh":
        return AUTH_REFRESH_IP_RPM
    if method == "GET" and path == "/metrics":
        return METRICS_IP_RPM
    return None


def route_credential_dimension(method: str, path: str) -> tuple[str, int]:
    if method == "GET" and path == "/api/v1/audit/events":
        return f"{method} {path}", AUDIT_EVENTS_CREDENTIAL_RPM
    if method == "GET" and path == "/api/v1/traffic-logs":
        return f"{method} {path}", TRAFFIC_LOGS_READ_CREDENTIAL_RPM
    if method == "POST" and path == "/api/v1/admin/reconcile":
        return f"{method} {path}", ADMIN_RECONCILE_CREDENTIAL_RPM
    if method == "GET" and path == "/api/v1/admin/overview":
        return f"{method} {path}", ADMIN_OVERVIEW_CREDENTIAL_RPM
    if method == "GET" and path == "/api/v1/admin/logs/stream":
        return f"{method} {path}", ADMIN_LOGS_STREAM_CREDENTIAL_RPM
    if method == "GET" and path.startswith("/api/v1/admin/"):
        return "GET /api/v1/admin/*", ADMIN_READ_CREDENTIAL_RPM
    if method == "POST" and path == "/internal/traffic-logs":
        return f"{method} {path}", TRAFFIC_LOG_INGEST_PRINCIPAL_RPM
    if method == "GET" and path == "/internal/sc-control/cvms":
        return f"{method} {path}", SC_CONTROL_RPM
    if method == "GET" and path == "/internal/dev-control/security-cvm-atls-policy":
        return f"{method} {path}", DEV_CONTROL_POLICY_RPM

    cvm_id = cvm_policy_bundle_route_id(method, path)
    if cvm_id is not None:
        return f"GET /api/v1/cvms/{{cvm_id}}/policy-bundle:{cvm_id}", POLICY_BUNDLE_CVM_RPM

    cvm_id = cvm_profile_mutation_route_id(method, path)
    if cvm_id is not None:
        return f"{method} /api/v1/cvms/{{cvm_id}}/profiles:{cvm_id}", CVM_PROFILE_MUTATION_RPM

    return f"{method} {path}", ROUTE_CREDENTIAL_RPM


UUID_SEGMENT_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def cvm_policy_bundle_route_id(method: str, path: str) -> str | None:
    if method != "GET":
        return None
    match = re.fullmatch(rf"/api/v1/cvms/({UUID_SEGMENT_RE.pattern})/policy-bundle", path)
    return match.group(1).lower() if match else None


def cvm_profile_mutation_route_id(method: str, path: str) -> str | None:
    if method == "POST":
        match = re.fullmatch(rf"/api/v1/cvms/({UUID_SEGMENT_RE.pattern})/profiles", path)
        return match.group(1).lower() if match else None
    if method == "DELETE":
        match = re.fullmatch(
            rf"/api/v1/cvms/({UUID_SEGMENT_RE.pattern})/profiles/{UUID_SEGMENT_RE.pattern}",
            path,
        )
        return match.group(1).lower() if match else None
    return None


def path_exempt_from_rate_limit(path: str) -> bool:
    return path == "/admin" or path.startswith("/admin/")


def prune_rate_limit_events(events: deque[float], now: float) -> None:
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    while events and events[0] <= cutoff:
        events.popleft()


def credential_fingerprint(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def clear_rate_limit_state() -> None:
    _rate_limit_events.clear()


def apply_response_headers(request: Request, response: Response, request_id: str) -> None:
    response.headers["X-Request-Id"] = request_id
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path == "/admin" or request.url.path.startswith("/admin/"):
        response.headers["Content-Security-Policy"] = ADMIN_CSP
    if request.url.path in {"/healthz", "/readyz"}:
        response.headers["Cache-Control"] = "public, max-age=60"
    else:
        response.headers.setdefault("Cache-Control", "no-store")


@app.get("/healthz", include_in_schema=False)
async def healthz(response: Response) -> dict[str, str]:
    response.headers["Cache-Control"] = "public, max-age=60"
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    checks = await run_ready_checks()
    status = 200 if all(value == "ok" for value in checks.values()) else 503
    return JSONResponse(
        status_code=status,
        content={"checks": checks},
        headers={"Cache-Control": "public, max-age=60"},
    )


def _admin_static_file(name: str) -> Path:
    static_dir = _admin_static_dir()
    path = (static_dir / name).resolve()
    if static_dir.resolve() not in path.parents and path != static_dir.resolve():
        raise HTTPException(status_code=404, detail="not found")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return path


@app.get("/admin", include_in_schema=False)
async def admin_index() -> Response:
    return _admin_file_response("index.html", "text/html; charset=utf-8")


@app.get("/admin/oauth/callback", include_in_schema=False)
async def admin_oauth_callback() -> Response:
    return _admin_file_response("oauth-callback.html", "text/html; charset=utf-8")


def _admin_asset_media_type(name: str) -> str:
    if name.endswith(".css"):
        return "text/css; charset=utf-8"
    if name.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if name.endswith(".svg"):
        return "image/svg+xml"
    if name.endswith(".woff2"):
        return "font/woff2"
    raise HTTPException(status_code=404, detail="not found")


@app.get("/admin/assets/{asset_path:path}", include_in_schema=False)
async def admin_assets(asset_path: str) -> Response:
    if not asset_path or ".." in asset_path or asset_path.startswith("/"):
        raise HTTPException(status_code=404, detail="not found")
    return _admin_file_response(asset_path, _admin_asset_media_type(asset_path))


def _admin_file_response(name: str, media_type: str) -> Response:
    path = _admin_static_file(name)
    cache_control = "no-store"
    if name.endswith(".svg") or name.endswith(".woff2"):
        cache_control = "public, max-age=300, must-revalidate"
    return Response(
        content=path.read_bytes(),
        media_type=media_type,
        headers={"Cache-Control": cache_control},
    )


@app.get("/metrics", include_in_schema=False)
async def metrics(authorization: Annotated[str | None, Header()] = None) -> PlainTextResponse:
    expected = load_settings().raw.get("METRICS_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="metrics token is not configured")
    supplied = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid metrics token")
    return PlainTextResponse(
        prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
