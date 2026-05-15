from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from concrete_console.audit import EMPTY_HASH, audit_row_hash
from concrete_console.routes import parse_audit_cursor


def test_audit_hash_matches_insert_payload_shape() -> None:
    row = {
        "seq": 1,
        "id": "00000000-0000-4000-8000-000000000001",
        "entity_id": "00000000-0000-4000-8000-000000000002",
        "actor_id": "00000000-0000-4000-8000-000000000003",
        "actor_email": "admin@example.com",
        "action": "USER_REGISTERED",
        "target_type": "user",
        "target_id": "00000000-0000-4000-8000-000000000004",
        "before": None,
        "after": {"email": "user@example.com"},
        "ip_address": "203.0.113.10",
        "description": "user registered",
        "request_id": "request-1",
        "timestamp": datetime(2026, 5, 15, 17, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        "prev_hash": EMPTY_HASH,
    }

    assert audit_row_hash(row) == audit_row_hash(dict(reversed(list(row.items()))))


def test_parse_audit_cursor_accepts_positive_integer() -> None:
    assert parse_audit_cursor("42") == 42


@pytest.mark.parametrize("cursor", ["not-a-number", "-1"])
def test_parse_audit_cursor_rejects_invalid_values(cursor: str) -> None:
    with pytest.raises(HTTPException) as exc:
        parse_audit_cursor(cursor)

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["code"] == "VALIDATION_ERROR"
