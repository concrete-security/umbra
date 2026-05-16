from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import asyncio
import json
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

import httpx


MAX_BATCH_ENTRIES = 1000
MAX_BATCH_BYTES = 4 * 1024 * 1024
DEFAULT_QUEUE_MAX_ENTRIES = 50_000
DEFAULT_QUEUE_MAX_BYTES = 50 * 1024 * 1024
RETRYABLE_STATUS_CODES = {429, 502, 503}


@dataclass(frozen=True)
class TrafficLogRecord:
    timestamp: datetime
    cvm_id: UUID
    source_ip: str
    destination_ip: str
    destination_host: str | None
    protocol: str
    port: int
    method: str | None
    path: str | None
    response_code: int | None
    bytes_transferred: int

    def to_json(self) -> dict[str, Any]:
        timestamp = self.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return {
            "timestamp": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "cvm_id": str(self.cvm_id),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_host": self.destination_host,
            "protocol": self.protocol,
            "port": self.port,
            "method": self.method,
            "path": self.path[:2000] if self.path is not None else None,
            "response_code": self.response_code,
            "bytes_transferred": self.bytes_transferred,
        }

    def approximate_size(self) -> int:
        return len(_compact_json(self.to_json()).encode("utf-8"))


@dataclass(frozen=True)
class TrafficLogBatch:
    idempotency_key: str
    records: tuple[TrafficLogRecord, ...]

    @classmethod
    def create(cls, records: list[TrafficLogRecord]) -> TrafficLogBatch:
        return cls(idempotency_key=uuid4().hex, records=tuple(records))

    def to_json(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "logs": [record.to_json() for record in self.records],
        }

    def body_bytes(self) -> bytes:
        return _compact_json(self.to_json()).encode("utf-8")


class TrafficLogQueue:
    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_QUEUE_MAX_ENTRIES,
        max_bytes: int = DEFAULT_QUEUE_MAX_BYTES,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self._records: deque[TrafficLogRecord] = deque()
        self._approx_bytes = 0
        self.dropped_oldest = 0

    def __len__(self) -> int:
        return len(self._records)

    def append(self, record: TrafficLogRecord) -> None:
        self._records.append(record)
        self._approx_bytes += record.approximate_size()
        while len(self._records) > self.max_entries or self._approx_bytes > self.max_bytes:
            dropped = self._records.popleft()
            self._approx_bytes -= dropped.approximate_size()
            self.dropped_oldest += 1

    def drain_batch(
        self,
        *,
        max_entries: int = MAX_BATCH_ENTRIES,
        max_bytes: int = MAX_BATCH_BYTES,
    ) -> TrafficLogBatch | None:
        if not self._records:
            return None
        records: list[TrafficLogRecord] = []
        while self._records and len(records) < max_entries:
            candidate = self._records[0]
            candidate_batch = TrafficLogBatch(idempotency_key="x" * 32, records=tuple([*records, candidate]))
            if records and len(candidate_batch.body_bytes()) > max_bytes:
                break
            records.append(self._records.popleft())
            self._approx_bytes -= candidate.approximate_size()
        return TrafficLogBatch.create(records)


class TrafficLogClient:
    def __init__(self, *, console_url: str, ingest_token: str, http: httpx.AsyncClient | None = None) -> None:
        if not console_url:
            raise ValueError("console_url is required")
        if not ingest_token:
            raise ValueError("ingest_token is required")
        self.console_url = console_url.rstrip("/")
        self.ingest_token = ingest_token
        self.http = http

    async def submit_with_retries(
        self,
        batch: TrafficLogBatch,
        *,
        max_attempts: int = 3,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> dict[str, Any]:
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        delay = 0.5
        last_response: httpx.Response | None = None
        for attempt in range(max_attempts):
            response = await self._post(batch)
            last_response = response
            if response.status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts - 1:
                await sleep(delay)
                delay = min(delay * 2, 8.0)
                continue
            response.raise_for_status()
            return response.json()
        assert last_response is not None
        last_response.raise_for_status()
        raise AssertionError("unreachable")

    async def _post(self, batch: TrafficLogBatch) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self.ingest_token}",
            "Content-Type": "application/json",
        }
        url = f"{self.console_url}/internal/traffic-logs"
        content = batch.body_bytes()
        if self.http is not None:
            return await self.http.post(url, headers=headers, content=content)
        async with httpx.AsyncClient(timeout=10.0) as http:
            return await http.post(url, headers=headers, content=content)


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
