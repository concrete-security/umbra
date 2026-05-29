from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Any

_BUFFER_SIZE = 1000
_LOCK = Lock()
_EVENTS: deque[dict[str, Any]] = deque(maxlen=_BUFFER_SIZE)
_LOG_STREAM_SEMAPHORE_SLOTS = 6
_log_stream_slots = 0
_log_stream_lock = Lock()

_CAPTURE_KEYS = (
    "event",
    "level",
    "timestamp",
    "route",
    "request_id",
    "method",
    "status",
    "duration_ms",
    "error_type",
    "actor_id",
)


def capture_log_event(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    entry = {key: event_dict[key] for key in _CAPTURE_KEYS if key in event_dict}
    if "event" not in entry:
        entry["event"] = event_dict.get("event", "log")
    if "level" not in entry:
        entry["level"] = event_dict.get("level", "info")
    with _LOCK:
        _EVENTS.append(entry)
    return event_dict


def recent_log_events(*, limit: int = 200) -> list[dict[str, Any]]:
    capped = max(1, min(limit, _BUFFER_SIZE))
    with _LOCK:
        return list(_EVENTS)[-capped:]


def acquire_log_stream_slot() -> bool:
    global _log_stream_slots
    with _log_stream_lock:
        if _log_stream_slots >= _LOG_STREAM_SEMAPHORE_SLOTS:
            return False
        _log_stream_slots += 1
        return True


def release_log_stream_slot() -> None:
    global _log_stream_slots
    with _log_stream_lock:
        _log_stream_slots = max(0, _log_stream_slots - 1)
