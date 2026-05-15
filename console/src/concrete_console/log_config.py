from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

from concrete_console.config import load_settings

SENSITIVE_KEY_RE = re.compile(
    r"(authorization|bearer|token|secret|password|private_key|device_code|polling_secret|id_token|access_token)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_RE = re.compile(r"(Bearer\s+[A-Za-z0-9._~-]+|-----BEGIN [A-Z ]+-----)")


def configure_logging() -> None:
    level_name = load_settings().raw.get("LOG_LEVEL", "info").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(stream=sys.stdout, format="%(message)s", level=level)
    logging.getLogger("asyncpg").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
            redact_log_values,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def bind_request_context(*, request_id: str) -> None:
    structlog.contextvars.bind_contextvars(request_id=request_id)


def bind_actor(actor_id: str) -> None:
    structlog.contextvars.bind_contextvars(actor_id=actor_id)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()


def logger():
    return structlog.get_logger("concrete_console")


def redact_log_values(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return _redact_mapping(event_dict)


def _redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    return {key: _redact_value(key, item) for key, item in value.items()}


def _redact_value(key: str, value: Any) -> Any:
    if key in {"request_id", "actor_id", "route", "event", "method", "status", "duration_ms", "level", "timestamp"}:
        return value
    if SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, str) and SENSITIVE_VALUE_RE.search(value):
        return "<redacted>"
    return value
