from contextlib import asynccontextmanager
import hmac
from typing import Annotated, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from concrete_console.config import load_settings
from concrete_console.db import close_pool
from concrete_console.metrics import monotonic_seconds, observe_request, prometheus_text
from concrete_console.readiness import run_ready_checks
from concrete_console.routes_auth import router as auth_router
from concrete_console.routes import router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        await close_pool()


app = FastAPI(title="Concrete Console", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(router)


@app.middleware("http")
async def record_request_metrics(request: Request, call_next):
    started = monotonic_seconds()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        route_label = getattr(route, "path", request.url.path)
        observe_request(
            route=route_label,
            method=request.method,
            status=status,
            duration_seconds=monotonic_seconds() - started,
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "ERROR", "message": str(exc.detail), "details": {}}},
    )


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
