from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

import asyncpg

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
POSTGRES_SCHEMES = {"postgres", "postgresql"}
DEFAULT_POSTGRES_EXPORT_TABLE = "concrete_audit_export_artifacts"
POSTGRES_EXPORT_TIMEOUT_SECONDS = 5.0
SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class AuditExportStorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditExportArtifact:
    content: bytes
    content_type: str
    sha256: str
    row_count: int
    byte_size: int


@dataclass(frozen=True)
class PostgresExportTarget:
    dsn: str
    table: str
    public_uri: str


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


def audit_export_storage_uri(bucket_uri: str, object_key: str) -> str:
    parsed = urlparse(bucket_uri)
    if parsed.scheme == "file":
        return file_artifact_path(bucket_uri, object_key).as_uri()
    if parsed.scheme in POSTGRES_SCHEMES:
        return f"{postgres_export_target(bucket_uri).public_uri}#objects/{quote(object_key, safe='')}"
    raise ValueError("AUDIT_EXPORT_BUCKET must use file:// or postgresql://")


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


def file_artifact_path(bucket_uri: str, object_key: str) -> Path:
    root = file_bucket_root(bucket_uri)
    path = (root / object_key).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("audit export object key escapes bucket root")
    return path


def write_file_artifact(bucket_uri: str, object_key: str, content: bytes) -> str:
    path = file_artifact_path(bucket_uri, object_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content)
    return path.as_uri()


def read_file_artifact(storage_uri: str) -> bytes:
    return file_bucket_root(storage_uri).read_bytes()


async def write_audit_export_artifact(bucket_uri: str, object_key: str, artifact: AuditExportArtifact) -> str:
    parsed = urlparse(bucket_uri)
    try:
        if parsed.scheme == "file":
            return write_file_artifact(bucket_uri, object_key, artifact.content)
        if parsed.scheme in POSTGRES_SCHEMES:
            return await write_postgres_artifact(postgres_export_target(bucket_uri), object_key, artifact)
    except (OSError, ValueError, asyncpg.PostgresError) as exc:
        raise AuditExportStorageError("audit export storage backend failed") from exc
    raise AuditExportStorageError("AUDIT_EXPORT_BUCKET must use file:// or postgresql://")


async def read_audit_export_artifact(bucket_uri: str, storage_uri: str) -> bytes:
    parsed = urlparse(storage_uri)
    try:
        if parsed.scheme == "file":
            return read_file_artifact(storage_uri)
        if parsed.scheme in POSTGRES_SCHEMES:
            object_key = postgres_storage_object_key(storage_uri)
            return await read_postgres_artifact(postgres_export_target(bucket_uri), object_key)
    except (OSError, ValueError, asyncpg.PostgresError) as exc:
        raise AuditExportStorageError("audit export storage backend failed") from exc
    raise AuditExportStorageError("unsupported audit export storage URI")


def postgres_export_target(bucket_uri: str) -> PostgresExportTarget:
    parsed = urlparse(bucket_uri)
    if parsed.scheme not in POSTGRES_SCHEMES:
        raise ValueError("AUDIT_EXPORT_BUCKET must use postgresql:// for this backend")
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    table_values = [value for key, value in query_items if key == "table"]
    if len(table_values) > 1:
        raise ValueError("AUDIT_EXPORT_BUCKET must include at most one table query parameter")
    table = table_values[0] if table_values else DEFAULT_POSTGRES_EXPORT_TABLE
    if not SQL_IDENTIFIER_RE.fullmatch(table):
        raise ValueError("AUDIT_EXPORT_BUCKET table must be an unqualified SQL identifier")
    dsn_query = urlencode([(key, value) for key, value in query_items if key != "table"])
    dsn = urlunparse(parsed._replace(query=dsn_query, fragment=""))
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    public_query = urlencode([("table", table)])
    public_uri = urlunparse((parsed.scheme, host, parsed.path, "", public_query, ""))
    return PostgresExportTarget(dsn=dsn, table=table, public_uri=public_uri)


async def write_postgres_artifact(target: PostgresExportTarget, object_key: str, artifact: AuditExportArtifact) -> str:
    conn = await asyncpg.connect(target.dsn, timeout=POSTGRES_EXPORT_TIMEOUT_SECONDS)
    try:
        await conn.execute(
            f"""
            INSERT INTO {quoted_identifier(target.table)} (
                object_key, content, content_type, content_sha256, row_count, byte_size
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            object_key,
            artifact.content,
            artifact.content_type,
            artifact.sha256,
            artifact.row_count,
            artifact.byte_size,
        )
    finally:
        await conn.close()
    return f"{target.public_uri}#objects/{quote(object_key, safe='')}"


async def read_postgres_artifact(target: PostgresExportTarget, object_key: str) -> bytes:
    conn = await asyncpg.connect(target.dsn, timeout=POSTGRES_EXPORT_TIMEOUT_SECONDS)
    try:
        content = await conn.fetchval(
            f"""
            SELECT content
            FROM {quoted_identifier(target.table)}
            WHERE object_key = $1
            """,
            object_key,
        )
    finally:
        await conn.close()
    if content is None:
        raise ValueError("audit export object was not found")
    return bytes(content)


def postgres_storage_object_key(storage_uri: str) -> str:
    parsed = urlparse(storage_uri)
    if parsed.scheme not in POSTGRES_SCHEMES or not parsed.fragment.startswith("objects/"):
        raise ValueError("invalid postgres audit export storage URI")
    object_key = unquote(parsed.fragment.removeprefix("objects/"))
    if not object_key.startswith("audit-exports/") or ".." in object_key.split("/"):
        raise ValueError("invalid postgres audit export object key")
    return object_key


def quoted_identifier(identifier: str) -> str:
    if not SQL_IDENTIFIER_RE.fullmatch(identifier):
        raise ValueError("invalid SQL identifier")
    return f'"{identifier}"'


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
