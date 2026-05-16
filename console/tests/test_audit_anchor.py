import asyncio
from datetime import datetime, timedelta, timezone

from concrete_console import audit_anchor


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


def test_postgres_anchor_target_strips_credentials_from_public_uri() -> None:
    target = audit_anchor.parse_postgres_anchor_target(
        "postgresql://anchor:secret@db.example:5432/audit?sslmode=require&table=anchors"
    )

    assert target.dsn == "postgresql://anchor:secret@db.example:5432/audit?sslmode=require"
    assert target.table == "anchors"
    assert target.public_uri == "postgresql://db.example:5432/audit?table=anchors"


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
