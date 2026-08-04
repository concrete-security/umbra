import asyncio
import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from umbra_console.audit import EMPTY_HASH, audit_row_hash, redact_email_payload
from umbra_console.routes import parse_audit_cursor


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


def test_redact_email_payload_rewrites_nested_email_values() -> None:
    payload = {
        "email": "dev@example.com",
        "name": "Dev User",
        "nested": [{"email": "dev@example.com"}, {"email": "other@example.com"}],
    }

    redacted, changed = redact_email_payload(
        payload,
        email="dev@example.com",
        replacement="<erased-abc123>@example.com",
    )

    assert changed is True
    assert redacted == {
        "email": "<erased-abc123>@example.com",
        "name": "Dev User",
        "nested": [{"email": "<erased-abc123>@example.com"}, {"email": "other@example.com"}],
    }


def test_parse_audit_cursor_accepts_positive_integer() -> None:
    assert parse_audit_cursor("42") == 42


@pytest.mark.parametrize("cursor", ["not-a-number", "-1"])
def test_parse_audit_cursor_rejects_invalid_values(cursor: str) -> None:
    with pytest.raises(HTTPException) as exc:
        parse_audit_cursor(cursor)

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["code"] == "VALIDATION_ERROR"


class RedactionConn:
    """Fake conn for redact_user_audit_trail: serves rows, records UPDATEs."""

    def __init__(self, rows):
        self.rows = rows
        self.updates = []

    async def execute(self, sql, *args):
        if "UPDATE audit_events" in sql:
            self.updates.append(args)
        return "OK"

    async def fetch(self, sql):
        return self.rows


def _audit_row(seq, *, actor_email, before=None, after=None, prev_hash, row_hash):
    return {
        "seq": seq,
        "id": f"00000000-0000-4000-8000-00000000000{seq}",
        "entity_id": "00000000-0000-4000-8000-000000000002",
        "actor_id": "00000000-0000-4000-8000-000000000003",
        "actor_email": actor_email,
        "action": "USER_REGISTERED",
        "target_type": "user",
        "target_id": "00000000-0000-4000-8000-000000000004",
        "before": before,
        "after": after,
        "ip_address": None,
        "description": "user registered",
        "request_id": None,
        "timestamp": datetime(2026, 5, 15, 17, 0, tzinfo=timezone.utc),
        "prev_hash": prev_hash,
        "row_hash": row_hash,
    }


def test_redact_user_audit_trail_rehashes_unchanged_rows_after_a_change(monkeypatch) -> None:
    """Regression for 34a6b3f: `_json_payload`'s def line was consumed by the
    re-anchor edit, so any redaction reaching an unchanged row (or finishing at
    all) raised NameError and 500'd the GDPR erase path."""
    import umbra_console.audit_anchor as audit_anchor_module
    from umbra_console.audit import redact_user_audit_trail

    reanchors = []

    async def fake_reanchor(conn, *, first_redacted_seq):
        reanchors.append(first_redacted_seq)

    monkeypatch.setattr(audit_anchor_module, "publish_audit_chain_redaction_reanchor", fake_reanchor)

    # seq 1 mentions the erased email (changed); seq 2 does not (unchanged, but
    # must be re-hashed onto the new chain) and carries its payload as a JSON
    # string, the shape asyncpg returns and _json_payload must parse.
    rows = [
        _audit_row(
            1,
            actor_email="dev@example.com",
            after={"email": "dev@example.com"},
            prev_hash=EMPTY_HASH,
            row_hash="a" * 64,
        ),
        _audit_row(
            2,
            actor_email="admin@example.com",
            before='{"note": "unrelated"}',
            prev_hash="a" * 64,
            row_hash="b" * 64,
        ),
    ]
    conn = RedactionConn(rows)

    asyncio.run(
        redact_user_audit_trail(conn, email="dev@example.com", replacement="<erased-x>@example.com")
    )

    assert reanchors == [1]
    assert len(conn.updates) == 2
    seq1 = conn.updates[0]
    assert seq1[0] == 1
    assert seq1[1] == "<erased-x>@example.com"
    assert json.loads(seq1[3]) == {"email": "<erased-x>@example.com"}
    seq2 = conn.updates[1]
    assert seq2[0] == 2
    assert seq2[1] == "admin@example.com"
    # The unchanged row's stringified payload was parsed, not double-encoded.
    assert json.loads(seq2[2]) == {"note": "unrelated"}
    # The chain re-links: seq 2's prev_hash is seq 1's new row_hash.
    assert seq2[4] == seq1[5]


def test_redact_user_audit_trail_no_matches_is_a_noop(monkeypatch) -> None:
    import umbra_console.audit_anchor as audit_anchor_module
    from umbra_console.audit import redact_user_audit_trail

    async def fail_reanchor(conn, *, first_redacted_seq):
        raise AssertionError("re-anchor must not run when nothing changed")

    monkeypatch.setattr(audit_anchor_module, "publish_audit_chain_redaction_reanchor", fail_reanchor)
    conn = RedactionConn(
        [
            _audit_row(
                1,
                actor_email="admin@example.com",
                prev_hash=EMPTY_HASH,
                row_hash="a" * 64,
            )
        ]
    )

    asyncio.run(redact_user_audit_trail(conn, email="dev@example.com", replacement="<erased-x>@example.com"))

    assert conn.updates == []
