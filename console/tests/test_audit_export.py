from datetime import datetime, timezone
from uuid import UUID

from concrete_console.audit_export import (
    audit_export_object_key,
    csv_safe_cell,
    file_bucket_root,
    serialize_audit_export,
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
