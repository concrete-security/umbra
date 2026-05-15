from contextlib import asynccontextmanager
import hmac
import re
from typing import Annotated, AsyncIterator
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from concrete_console.config import load_settings
from concrete_console.db import close_pool
from concrete_console.log_config import bind_request_context, clear_context, configure_logging, logger
from concrete_console.metrics import monotonic_seconds, observe_request, prometheus_text
from concrete_console.readiness import run_ready_checks, verify_configured_phala_cli
from concrete_console.routes_auth import router as auth_router
from concrete_console.routes_internal import router as internal_router
from concrete_console.routes import router
from concrete_console.scheduler import start_operation_scheduler, stop_operation_scheduler

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}

configure_logging()
log = logger()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await verify_configured_phala_cli(fetch_timeout=5.0)
    scheduler_task = start_operation_scheduler()
    try:
        yield
    finally:
        await stop_operation_scheduler(scheduler_task)
        await close_pool()


app = FastAPI(title="Concrete Console", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(internal_router)
app.include_router(router)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = resolve_request_id(request)
    request.state.request_id = request_id
    bind_request_context(request_id=request_id)
    started = monotonic_seconds()
    status = 500
    try:
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


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        detail = exc.detail.copy()
        detail["error"] = {**detail["error"], "request_id": request_id}
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "ERROR",
                "message": str(exc.detail),
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


def apply_response_headers(request: Request, response: Response, request_id: str) -> None:
    response.headers["X-Request-Id"] = request_id
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
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
