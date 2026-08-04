from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Mapping
from uuid import UUID, uuid4

import httpx


logger = logging.getLogger(__name__)

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
    attributes: Mapping[str, str] = field(default_factory=dict)
    # The enforcement decision that produced this record: "allowed", a block
    # reason (e.g. "secret_injection_unfulfilled", "dlp_secret_detected"), or
    # "websocket_frame_dropped". Lets a blocked request be diagnosed from the
    # logs by reason without reproducing it (docs/specs/security-cvm.md §6.1).
    decision: str | None = None

    def to_json(self) -> dict[str, Any]:
        timestamp = self.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        payload: dict[str, Any] = {
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
            "decision": self.decision,
            "bytes_transferred": self.bytes_transferred,
        }
        if self.attributes:
            payload["attributes"] = dict(self.attributes)
        return payload

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

    @property
    def approximate_bytes(self) -> int:
        return self._approx_bytes

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


@dataclass(frozen=True)
class TrafficLogEmitterStats:
    queued_records: int
    queued_approx_bytes: int
    pending_records: int
    dropped_oldest: int
    dropped_unretryable_batches: int
    dropped_unretryable_records: int
    submitted_batches: int
    submitted_records: int
    failed_attempts: int


class TrafficLogEmitter:
    def __init__(
        self,
        *,
        queue: TrafficLogQueue,
        client: TrafficLogClient,
        flush_interval_seconds: float = 1.0,
        max_batch_entries: int = MAX_BATCH_ENTRIES,
        max_batch_bytes: int = MAX_BATCH_BYTES,
        max_submit_attempts: int = 3,
    ) -> None:
        if flush_interval_seconds <= 0:
            raise ValueError("flush_interval_seconds must be positive")
        if max_batch_entries <= 0:
            raise ValueError("max_batch_entries must be positive")
        if max_batch_bytes <= 0:
            raise ValueError("max_batch_bytes must be positive")
        if max_submit_attempts <= 0:
            raise ValueError("max_submit_attempts must be positive")
        self.queue = queue
        self.client = client
        self.flush_interval_seconds = flush_interval_seconds
        self.max_batch_entries = max_batch_entries
        self.max_batch_bytes = max_batch_bytes
        self.max_submit_attempts = max_submit_attempts
        self._flush_event = asyncio.Event()
        self._pending_batch: TrafficLogBatch | None = None
        self._submitted_batches = 0
        self._submitted_records = 0
        self._failed_attempts = 0
        self._dropped_unretryable_batches = 0
        self._dropped_unretryable_records = 0

    def enqueue(self, record: TrafficLogRecord) -> None:
        before_dropped = self.queue.dropped_oldest
        self.queue.append(record)
        if self.queue.dropped_oldest > before_dropped:
            logger.error(
                "traffic_log_queue_dropped_oldest",
                extra={
                    "dropped_oldest": self.queue.dropped_oldest,
                    "queued_records": len(self.queue),
                    "queued_approx_bytes": self.queue.approximate_bytes,
                },
            )
        if self.should_flush():
            self._flush_event.set()

    def should_flush(self) -> bool:
        return (
            self._pending_batch is not None
            or len(self.queue) >= self.max_batch_entries
            or self.queue.approximate_bytes >= self.max_batch_bytes
        )

    async def flush_once(
        self,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> bool:
        self._flush_event.clear()
        if self._pending_batch is None:
            self._pending_batch = self.queue.drain_batch(
                max_entries=self.max_batch_entries,
                max_bytes=self.max_batch_bytes,
            )
        if self._pending_batch is None:
            return False
        batch = self._pending_batch
        try:
            await self.client.submit_with_retries(
                batch,
                max_attempts=self.max_submit_attempts,
                sleep=sleep,
            )
        except httpx.HTTPStatusError as exc:
            self._failed_attempts += 1
            if exc.response.status_code in RETRYABLE_STATUS_CODES:
                logger.error(
                    "traffic_log_batch_retryable_failure",
                    extra={
                        "status_code": exc.response.status_code,
                        "records": len(batch.records),
                    },
                )
                return False
            self._drop_unretryable_batch(batch, status_code=exc.response.status_code)
            return False
        except httpx.HTTPError as exc:
            self._failed_attempts += 1
            logger.error(
                "traffic_log_batch_transport_failure",
                extra={
                    "error_type": type(exc).__name__,
                    "records": len(batch.records),
                },
            )
            return False
        self._submitted_batches += 1
        self._submitted_records += len(batch.records)
        self._pending_batch = None
        if self.should_flush():
            self._flush_event.set()
        return True

    async def wait_until_due(self) -> None:
        if self.should_flush():
            return
        try:
            await asyncio.wait_for(self._flush_event.wait(), timeout=self.flush_interval_seconds)
        except TimeoutError:
            pass
        finally:
            self._flush_event.clear()

    def stats(self) -> TrafficLogEmitterStats:
        return TrafficLogEmitterStats(
            queued_records=len(self.queue),
            queued_approx_bytes=self.queue.approximate_bytes,
            pending_records=0 if self._pending_batch is None else len(self._pending_batch.records),
            dropped_oldest=self.queue.dropped_oldest,
            dropped_unretryable_batches=self._dropped_unretryable_batches,
            dropped_unretryable_records=self._dropped_unretryable_records,
            submitted_batches=self._submitted_batches,
            submitted_records=self._submitted_records,
            failed_attempts=self._failed_attempts,
        )

    def _drop_unretryable_batch(self, batch: TrafficLogBatch, *, status_code: int) -> None:
        self._dropped_unretryable_batches += 1
        self._dropped_unretryable_records += len(batch.records)
        self._pending_batch = None
        logger.error(
            "traffic_log_batch_unretryable_failure",
            extra={
                "status_code": status_code,
                "records": len(batch.records),
            },
        )


async def run_traffic_log_emitter_loop(
    emitter: TrafficLogEmitter,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_iterations: int | None = None,
) -> None:
    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        await emitter.flush_once(sleep=sleep)
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            break
        await emitter.wait_until_due()


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
