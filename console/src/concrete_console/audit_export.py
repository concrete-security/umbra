from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from concrete_console.resources import audit_event_resource

CSV_COLUMNS = (
    "seq",
    "id",
    "entity_id",
    "actor_id",
    "actor_email",
    "action",
    "target_type",
    "target_id",
    "before",
    "after",
    "ip_address",
    "description",
    "request_id",
    "timestamp",
    "prev_hash",
    "row_hash",
)
DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "|", "\t", "\r", "\n")


@dataclass(frozen=True)
class AuditExportArtifact:
    content: bytes
    content_type: str
    sha256: str
    row_count: int
    byte_size: int


def serialize_audit_export(rows: list[Any], export_format: str) -> AuditExportArtifact:
    records = [audit_event_resource(row) for row in rows]
    if export_format == "csv":
        content = _serialize_csv(records)
        content_type = "text/csv; charset=utf-8"
    elif export_format == "ndjson":
        content = _serialize_ndjson(records)
        content_type = "application/x-ndjson"
    else:
        raise ValueError(f"unsupported audit export format: {export_format}")
    return AuditExportArtifact(
        content=content,
        content_type=content_type,
        sha256=hashlib.sha256(content).hexdigest(),
        row_count=len(records),
        byte_size=len(content),
    )


def audit_export_extension(export_format: str) -> str:
    if export_format == "csv":
        return "csv"
    if export_format == "ndjson":
        return "ndjson"
    raise ValueError(f"unsupported audit export format: {export_format}")


def audit_export_object_key(operation_id: Any, export_format: str) -> str:
    return f"audit-exports/{operation_id}.{audit_export_extension(export_format)}"


def file_bucket_root(bucket_uri: str) -> Path:
    parsed = urlparse(bucket_uri)
    if parsed.scheme != "file":
        raise ValueError("AUDIT_EXPORT_BUCKET must use file:// for this local backend")
    if parsed.netloc not in {"", "localhost"}:
        raise ValueError("file AUDIT_EXPORT_BUCKET must not include a remote host")
    root = Path(unquote(parsed.path))
    if not root.is_absolute():
        raise ValueError("file AUDIT_EXPORT_BUCKET must be an absolute path")
    return root


def write_file_artifact(bucket_uri: str, object_key: str, content: bytes) -> str:
    root = file_bucket_root(bucket_uri)
    path = (root / object_key).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("audit export object key escapes bucket root")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content)
    return path.as_uri()


def read_file_artifact(storage_uri: str) -> bytes:
    return file_bucket_root(storage_uri).read_bytes()


def csv_safe_cell(value: Any) -> str:
    text = _cell_text(value)
    stripped = text.lstrip()
    dangerous = bool(stripped and stripped[0] in DANGEROUS_CSV_PREFIXES)
    if text and text[0] in {"\t", "\r", "\n"}:
        dangerous = True
    text = text.replace("\r", " ").replace("\n", " ")
    return f"'{text}" if dangerous else text


def _serialize_csv(records: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        writer.writerow({column: csv_safe_cell(record.get(column)) for column in CSV_COLUMNS})
    return output.getvalue().encode("utf-8")


def _serialize_ndjson(records: list[dict[str, Any]]) -> bytes:
    lines = [
        json.dumps(record, sort_keys=True, separators=(",", ":"), default=_json_default)
        for record in records
    ]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_default)
    return str(value)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return str(value)
