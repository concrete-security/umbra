import asyncio
from datetime import datetime, timedelta, timezone
import re
from uuid import UUID

import pytest

from umbra_console import audit_anchor
from umbra_console.audit import EMPTY_HASH, audit_row_hash
from umbra_console.metrics import prometheus_text


class FakeConn:
    def __init__(self, *, latest_event=None, latest_anchor=None):
        self.latest_event = latest_event
        self.latest_anchor = latest_anchor
        self.fetchrow_calls: list[str] = []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append(query)
        if "FROM audit_events" in query:
            return self.latest_event
        if "FROM audit_anchors" in query:
            return self.latest_anchor
        raise AssertionError(query)

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "INSERT 0 1"


class ReplayConn:
    def __init__(self, rows, *, latest_anchor=None):
        self.rows = rows
        self.latest_anchor = latest_anchor
        self.replay_fetches = 0
        self.lock_attempts = 0
        self.unlocks = 0

    async def fetchrow(self, query, *args):
        assert "FROM audit_anchors" in query
        return self.latest_anchor

    async def fetch(self, query, *args):
        assert "FROM audit_events" in query
        self.replay_fetches += 1
        return self.rows

    async def fetchval(self, query, *args):
        assert "pg_try_advisory_lock" in query
        self.lock_attempts += 1
        return True

    async def execute(self, query, *args):
        assert "pg_advisory_unlock" in query
        self.unlocks += 1
        return "SELECT 1"


def _audit_rows(count: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    prev_hash = EMPTY_HASH
    for seq in range(1, count + 1):
        event_timestamp = datetime(2026, 5, 16, 9, 0, seq, tzinfo=timezone.utc)
        payload = {
            "seq": seq,
            "id": f"00000000-0000-4000-8000-{seq:012d}",
            "entity_id": "00000000-0000-4000-8000-000000000100",
            "actor_id": "00000000-0000-4000-8000-000000000200",
            "actor_email": "admin@example.com",
            "action": "USER_REGISTERED",
            "target_type": "user",
            "target_id": f"00000000-0000-4000-8000-{seq:012d}",
            "before": None,
            "after": {"seq": seq},
            "ip_address": None,
            "description": "user registered",
            "request_id": None,
            "timestamp": event_timestamp.isoformat().replace("+00:00", "Z"),
            "prev_hash": prev_hash,
        }
        row_hash = audit_row_hash(payload)
        rows.append({**payload, "timestamp": event_timestamp, "row_hash": row_hash})
        prev_hash = row_hash
    return rows


def _anchor_records(row: dict[str, object], *, anchored_at: datetime) -> tuple[dict, dict]:
    anchor_id = UUID("00000000-0000-4000-8000-000000000300")
    payload = audit_anchor.anchor_payload(
        last_seq=int(row["seq"]),
        last_row_hash=str(row["row_hash"]),
        anchored_at=anchored_at,
        console_kid="kid-1",
    )
    digest = audit_anchor.anchor_digest(payload)
    local = {
        "id": anchor_id,
        "last_seq": row["seq"],
        "last_row_hash": row["row_hash"],
        "external_anchor_uri": f"postgresql://db.example/audit?table=anchors#anchors/{anchor_id}",
        "external_anchor_digest": digest,
        "anchored_at": anchored_at,
    }
    external = {
        "id": anchor_id,
        "last_seq": row["seq"],
        "last_row_hash": row["row_hash"],
        "anchored_at": anchored_at,
        "console_kid": "kid-1",
        "payload": payload,
        "payload_sha256": digest,
    }
    return local, external


def _audit_failure_metric() -> int:
    match = re.search(r"umbra_console_audit_chain_verification_failures_total (\d+)", prometheus_text())
    assert match is not None
    return int(match.group(1))


@pytest.mark.parametrize(
    ("target_uri", "expected_dsn", "expected_table", "expected_public_uri"),
    [
        pytest.param(
            "postgresql://anchor:secret@db.example:5432/audit?sslmode=require&table=anchors",
            "postgresql://anchor:secret@db.example:5432/audit?sslmode=require",
            "anchors",
            "postgresql://db.example:5432/audit?table=anchors",
            id="explicit-table",
        ),
        pytest.param(
            "postgresql://anchor:secret@db.example:5432/audit?sslmode=require",
            "postgresql://anchor:secret@db.example:5432/audit?sslmode=require",
            "umbra_audit_anchors",
            "postgresql://db.example:5432/audit?table=umbra_audit_anchors",
            id="umbra-default",
        ),
    ],
)
def test_postgres_anchor_target_parsing_success(
    target_uri: str,
    expected_dsn: str,
    expected_table: str,
    expected_public_uri: str,
) -> None:
    """Parsing keeps credentials private and selects explicit or Umbra tables."""

    target = audit_anchor.parse_postgres_anchor_target(target_uri)

    assert target.dsn == expected_dsn
    assert target.table == expected_table
    assert target.public_uri == expected_public_uri


def test_anchor_payload_digest_uses_canonical_json() -> None:
    payload = audit_anchor.anchor_payload(
        last_seq=7,
        last_row_hash="a" * 64,
        anchored_at=datetime(2026, 5, 16, 9, 0, tzinfo=timezone.utc),
        console_kid="kid-1",
    )

    assert payload == {
        "anchored_at": "2026-05-16T09:00:00Z",
        "console_kid": "kid-1",
        "last_row_hash": "a" * 64,
        "last_seq": 7,
    }
    assert audit_anchor.anchor_digest(payload) == audit_anchor.anchor_digest(dict(reversed(payload.items())))


def test_publish_anchor_if_due_writes_external_and_local_rows(monkeypatch) -> None:
    written: list[tuple[audit_anchor.PostgresAnchorTarget, dict, str]] = []

    monkeypatch.setenv("AUDIT_ANCHOR_TARGET", "postgresql://anchor:secret@db.example/audit?table=anchors")
    monkeypatch.setenv("AUDIT_ANCHOR_INTERVAL_SECONDS", "3600")
    monkeypatch.setenv("JWT_ACTIVE_KID", "kid-1")

    async def write_external(target, *, anchor_id, payload, payload_sha256):
        written.append((target, payload, payload_sha256))

    monkeypatch.setattr(audit_anchor, "write_postgres_anchor", write_external)
    now = datetime(2026, 5, 16, 9, 0, tzinfo=timezone.utc)
    conn = FakeConn(latest_event={"seq": 42, "row_hash": "b" * 64}, latest_anchor=None)

    publication = asyncio.run(audit_anchor.publish_audit_anchor_if_due(conn, now=now))

    assert publication is not None
    assert publication.last_seq == 42
    assert publication.last_row_hash == "b" * 64
    assert publication.external_anchor_digest == written[0][2]
    target, payload, digest = written[0]
    assert target.public_uri == "postgresql://db.example/audit?table=anchors"
    assert payload == {
        "anchored_at": "2026-05-16T09:00:00Z",
        "console_kid": "kid-1",
        "last_row_hash": "b" * 64,
        "last_seq": 42,
    }
    assert digest == audit_anchor.anchor_digest(payload)
    query, args = conn.execute_calls[0]
    assert "INSERT INTO audit_anchors" in query
    assert args[1:6] == (
        42,
        "b" * 64,
        publication.external_anchor_uri,
        digest,
        now,
    )


def test_publish_anchor_if_due_skips_recent_anchor(monkeypatch) -> None:
    monkeypatch.setenv("AUDIT_ANCHOR_TARGET", "postgresql://anchor:secret@db.example/audit")
    monkeypatch.setenv("AUDIT_ANCHOR_INTERVAL_SECONDS", "3600")
    now = datetime(2026, 5, 16, 9, 0, tzinfo=timezone.utc)
    conn = FakeConn(
        latest_event={"seq": 42, "row_hash": "b" * 64},
        latest_anchor={"last_seq": 40, "anchored_at": now - timedelta(seconds=120)},
    )

    publication = asyncio.run(audit_anchor.publish_audit_anchor_if_due(conn, now=now))

    assert publication is None
    assert conn.execute_calls == []


def test_verify_audit_chain_accepts_post_anchor_tail_success(monkeypatch) -> None:
    """A valid anchor binds its own sequence while later linked rows remain valid."""

    monkeypatch.setenv("AUDIT_ANCHOR_TARGET", "postgresql://anchor:secret@db.example/audit?table=anchors")
    rows = _audit_rows(3)
    local, external = _anchor_records(rows[1], anchored_at=datetime(2026, 5, 16, 10, 0, tzinfo=timezone.utc))

    async def read_external(target, *, anchor_id):
        assert target.table == "anchors"
        assert anchor_id == local["id"]
        return external

    monkeypatch.setattr(audit_anchor, "read_postgres_anchor", read_external)

    asyncio.run(audit_anchor.verify_audit_chain(ReplayConn(rows, latest_anchor=local)))


def test_maybe_verify_audit_chain_deleted_row_gap_failure(monkeypatch) -> None:
    """Deleting a linked middle row breaks replay and increments the alert counter."""

    monkeypatch.delenv("AUDIT_ANCHOR_TARGET", raising=False)
    monkeypatch.setattr(audit_anchor, "_last_audit_chain_replay_wall", None)
    rows = _audit_rows(3)
    conn = ReplayConn([rows[0], rows[2]])
    before = _audit_failure_metric()

    with pytest.raises(audit_anchor.AuditChainVerificationError, match="link mismatch at seq 3"):
        asyncio.run(
            audit_anchor.maybe_verify_audit_chain(
                conn,
                now=datetime(2026, 5, 16, 10, 0, tzinfo=timezone.utc),
            )
        )

    assert _audit_failure_metric() == before + 1
    assert conn.unlocks == 1


def test_verify_audit_chain_external_anchor_tampering_failure(monkeypatch) -> None:
    """A self-consistent external rewrite still fails the immutable local commitment."""

    monkeypatch.setenv("AUDIT_ANCHOR_TARGET", "postgresql://anchor:secret@db.example/audit?table=anchors")
    rows = _audit_rows(2)
    anchored_at = datetime(2026, 5, 16, 10, 0, tzinfo=timezone.utc)
    local, external = _anchor_records(rows[-1], anchored_at=anchored_at)
    tampered_payload = audit_anchor.anchor_payload(
        last_seq=2,
        last_row_hash="f" * 64,
        anchored_at=anchored_at,
        console_kid="kid-1",
    )
    external.update(
        last_row_hash="f" * 64,
        payload=tampered_payload,
        payload_sha256=audit_anchor.anchor_digest(tampered_payload),
    )

    async def read_external(target, *, anchor_id):
        return external

    monkeypatch.setattr(audit_anchor, "read_postgres_anchor", read_external)

    with pytest.raises(audit_anchor.AuditChainVerificationError, match="does not match local commitment"):
        asyncio.run(audit_anchor.verify_audit_chain(ReplayConn(rows, latest_anchor=local)))


def test_maybe_verify_audit_chain_daily_cadence_success(monkeypatch) -> None:
    """The scheduler replays immediately, then suppresses repeats for one day."""

    monkeypatch.delenv("AUDIT_ANCHOR_TARGET", raising=False)
    monkeypatch.setattr(audit_anchor, "_last_audit_chain_replay_wall", None)
    conn = ReplayConn(_audit_rows(1))
    now = datetime(2026, 5, 16, 10, 0, tzinfo=timezone.utc)

    first = asyncio.run(audit_anchor.maybe_verify_audit_chain(conn, now=now))
    second = asyncio.run(audit_anchor.maybe_verify_audit_chain(conn, now=now + timedelta(hours=23)))

    assert first is True
    assert second is False
    assert conn.replay_fetches == 1
    assert conn.lock_attempts == 1
