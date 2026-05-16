import asyncio
from datetime import datetime, timezone
from uuid import UUID

from concrete_console.audit_export import (
    audit_export_object_key,
    audit_export_storage_uri,
    csv_safe_cell,
    file_bucket_root,
    postgres_export_target,
    read_audit_export_artifact,
    serialize_audit_export,
    write_audit_export_artifact,
    write_file_artifact,
)


def audit_row(**overrides):
    row = {
        "seq": 1,
        "id": UUID("00000000-0000-4000-8000-000000000001"),
        "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
        "actor_id": UUID("00000000-0000-4000-8000-000000000003"),
        "actor_email": "dev@example.com",
        "action": "USER_REGISTERED",
        "target_type": "user",
        "target_id": "00000000-0000-4000-8000-000000000003",
        "before": None,
        "after": {"email": "dev@example.com"},
        "ip_address": "127.0.0.1",
        "description": "user registered",
        "request_id": "request-1",
        "timestamp": datetime(2026, 5, 16, 1, 30, tzinfo=timezone.utc),
        "prev_hash": "0" * 64,
        "row_hash": "1" * 64,
    }
    row.update(overrides)
    return row


def test_csv_safe_cell_blocks_formula_and_line_injection() -> None:
    assert csv_safe_cell("=1+1") == "'=1+1"
    assert csv_safe_cell("  @cmd") == "'  @cmd"
    assert csv_safe_cell("\tSUM(A1:A2)") == "'\tSUM(A1:A2)"
    assert csv_safe_cell("safe\r\nvalue") == "safe  value"


def test_serialize_audit_export_ndjson_hashes_exact_bytes() -> None:
    artifact = serialize_audit_export([audit_row()], "ndjson")

    assert artifact.content_type == "application/x-ndjson"
    assert artifact.row_count == 1
    assert artifact.byte_size == len(artifact.content)
    assert artifact.content.endswith(b"\n")
    assert b'"action":"USER_REGISTERED"' in artifact.content


def test_serialize_audit_export_csv_includes_header_and_sanitized_values() -> None:
    artifact = serialize_audit_export([audit_row(actor_email="=cmd")], "csv")

    assert artifact.content_type == "text/csv; charset=utf-8"
    assert artifact.row_count == 1
    text = artifact.content.decode("utf-8")
    assert text.startswith("seq,id,entity_id")
    assert "'=cmd" in text


def test_file_bucket_requires_absolute_file_uri(tmp_path) -> None:
    bucket = tmp_path.as_uri()
    key = audit_export_object_key("00000000-0000-4000-8000-000000000001", "csv")
    storage_uri = write_file_artifact(bucket, key, b"payload")

    assert file_bucket_root(bucket) == tmp_path
    assert storage_uri.endswith("/audit-exports/00000000-0000-4000-8000-000000000001.csv")
    assert (tmp_path / key).read_bytes() == b"payload"


def test_audit_export_storage_uri_derives_supported_backend_locations(tmp_path) -> None:
    key = audit_export_object_key("00000000-0000-4000-8000-000000000001", "ndjson")

    assert audit_export_storage_uri(tmp_path.as_uri(), key).endswith(
        "/audit-exports/00000000-0000-4000-8000-000000000001.ndjson"
    )
    assert audit_export_storage_uri("postgresql://export:secret@db.example/audit?table=exports", key) == (
        "postgresql://db.example/audit?table=exports"
        "#objects/audit-exports%2F00000000-0000-4000-8000-000000000001.ndjson"
    )


def test_postgres_export_target_strips_credentials_from_public_uri() -> None:
    target = postgres_export_target(
        "postgresql://export:secret@db.example:5432/audit?sslmode=require&table=exports"
    )

    assert target.dsn == "postgresql://export:secret@db.example:5432/audit?sslmode=require"
    assert target.table == "exports"
    assert target.public_uri == "postgresql://db.example:5432/audit?table=exports"


def test_postgres_export_store_writes_and_reads_artifact(monkeypatch) -> None:
    artifact = serialize_audit_export([audit_row()], "ndjson")
    stored: dict[str, bytes] = {}
    queries: list[str] = []

    class FakeConn:
        async def execute(self, query: str, *args):
            queries.append(query)
            stored[args[0]] = bytes(args[1])

        async def fetchval(self, query: str, *args):
            queries.append(query)
            return stored.get(args[0])

        async def close(self) -> None:
            return None

    async def connect(dsn: str, *, timeout: float):
        assert dsn == "postgresql://export:secret@db.example/audit"
        assert timeout == 5.0
        return FakeConn()

    from concrete_console import audit_export

    monkeypatch.setattr(audit_export.asyncpg, "connect", connect)
    bucket = "postgresql://export:secret@db.example/audit?table=exports"
    key = audit_export_object_key("00000000-0000-4000-8000-000000000001", "ndjson")

    storage_uri = asyncio.run(write_audit_export_artifact(bucket, key, artifact))
    content = asyncio.run(read_audit_export_artifact(bucket, storage_uri))

    assert storage_uri == (
        "postgresql://db.example/audit?table=exports"
        "#objects/audit-exports%2F00000000-0000-4000-8000-000000000001.ndjson"
    )
    assert content == artifact.content
    assert 'INSERT INTO "exports"' in queries[0]
    assert 'FROM "exports"' in queries[1]
