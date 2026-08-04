from __future__ import annotations

import logging
import json
import re
import sys
from typing import Any

import structlog

from umbra_console.config import load_settings
from umbra_console.metrics import observe_redacted_value_in_log

SENSITIVE_KEY_RE = re.compile(
    r"(authorization|bearer|token|secret|password|private_key|device_code|polling_secret|id_token|access_token)",
    re.IGNORECASE,
)
SENSITIVE_EXACT_KEYS = {"before", "after", "ca_cert_pem", "ca_export_token_plaintext", "compose_config", "ingest_token_plaintext"}
SENSITIVE_VALUE_RE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~-]+|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"-----BEGIN [A-Z ]+-----|"
    r"sk-[A-Za-z0-9_-]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"A(?:KI|SI)A[0-9A-Z]{16})"
)
SAFE_KEYS = {"request_id", "actor_id", "route", "event", "method", "status", "duration_ms", "level", "timestamp"}


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
    return structlog.get_logger("umbra_console")


def redact_log_values(logger: Any, _: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    source = _source_name(logger)
    redacted, paths = _redact_mapping(event_dict, source=source, path=())
    for path in paths:
        observe_redacted_value_in_log(source=source)
        _emit_redaction_alarm(source=source, key=".".join(path))
    return redacted


def _redact_mapping(value: dict[str, Any], *, source: str, path: tuple[str, ...]) -> tuple[dict[str, Any], list[tuple[str, ...]]]:
    redacted: dict[str, Any] = {}
    paths: list[tuple[str, ...]] = []
    for key, item in value.items():
        item_path = (*path, str(key))
        redacted_value, item_paths = _redact_value(str(key), item, source=source, path=item_path)
        redacted[key] = redacted_value
        paths.extend(item_paths)
    return redacted, paths


def _redact_value(key: str, value: Any, *, source: str, path: tuple[str, ...]) -> tuple[Any, list[tuple[str, ...]]]:
    if key in SAFE_KEYS:
        return value, []
    if _is_sensitive_key(key):
        return "<redacted>", [path]
    if isinstance(value, dict):
        return _redact_mapping(value, source=source, path=path)
    if isinstance(value, list):
        redacted_items: list[Any] = []
        paths: list[tuple[str, ...]] = []
        for index, item in enumerate(value):
            redacted_item, item_paths = _redact_value(key, item, source=source, path=(*path, str(index)))
            redacted_items.append(redacted_item)
            paths.extend(item_paths)
        return redacted_items, paths
    if isinstance(value, str) and _is_sensitive_value(value):
        return "<redacted>", [path]
    return value, []


def _is_sensitive_value(value: str) -> bool:
    if SENSITIVE_VALUE_RE.search(value):
        return True
    return any(secret in value for secret in _configured_secret_values())


def _configured_secret_values() -> set[str]:
    secrets: set[str] = set()
    for key, value in load_settings().raw.items():
        if not value or len(value) < 8:
            continue
        if _is_sensitive_key(key):
            secrets.add(value)
    return secrets


def _is_sensitive_key(key: str) -> bool:
    return key.lower() in SENSITIVE_EXACT_KEYS or SENSITIVE_KEY_RE.search(key) is not None


def _source_name(logger: Any) -> str:
    name = getattr(logger, "name", None)
    if isinstance(name, str) and name:
        return name
    return "umbra_console"


def _emit_redaction_alarm(*, source: str, key: str) -> None:
    payload = {
        "event": "redacted_value_in_log",
        "level": "error",
        "key": key,
        "source": source,
    }
    logging.getLogger("umbra_console.redaction").error(json.dumps(payload, sort_keys=True))
