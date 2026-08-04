import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest

from umbra_security_cvm.traffic import (
    TrafficLogBatch,
    TrafficLogClient,
    TrafficLogEmitter,
    TrafficLogQueue,
    TrafficLogRecord,
    run_traffic_log_emitter_loop,
)


CVM_ID = UUID("00000000-0000-4000-8000-000000000010")


def record(**overrides: object) -> TrafficLogRecord:
    fields = {
        "timestamp": datetime(2026, 5, 16, 5, 45, tzinfo=timezone.utc),
        "cvm_id": CVM_ID,
        "source_ip": "10.0.0.5",
        "destination_ip": "140.82.114.6",
        "destination_host": "api.github.com",
        "protocol": "https",
        "port": 443,
        "method": "GET",
        "path": "/repos",
        "response_code": 200,
        "bytes_transferred": 1234,
    }
    fields.update(overrides)
    return TrafficLogRecord(**fields)  # type: ignore[arg-type]


def test_record_json_truncates_path_and_serializes_timestamp() -> None:
    payload = record(path="/" + "x" * 2500).to_json()

    assert payload["timestamp"] == "2026-05-16T05:45:00Z"
    assert payload["cvm_id"] == str(CVM_ID)
    assert len(payload["path"]) == 2000


def test_record_json_includes_decision() -> None:
    assert record().to_json()["decision"] is None
    assert (
        record(decision="secret_injection_unfulfilled").to_json()["decision"]
        == "secret_injection_unfulfilled"
    )


def test_queue_drops_oldest_when_bound_is_exceeded() -> None:
    queue = TrafficLogQueue(max_entries=2, max_bytes=10_000)

    queue.append(record(path="/first"))
    queue.append(record(path="/second"))
    queue.append(record(path="/third"))
    batch = queue.drain_batch()

    assert queue.dropped_oldest == 1
    assert batch is not None
    assert [item.path for item in batch.records] == ["/second", "/third"]
    assert len(queue) == 0


def test_emitter_logs_when_queue_drops_oldest(caplog: pytest.LogCaptureFixture) -> None:
    queue = TrafficLogQueue(max_entries=1, max_bytes=10_000)
    client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest")
    emitter = TrafficLogEmitter(queue=queue, client=client, max_batch_entries=100)

    with caplog.at_level(logging.ERROR, logger="umbra_security_cvm.traffic"):
        emitter.enqueue(record(path="/first"))
        emitter.enqueue(record(path="/second"))

    assert queue.dropped_oldest == 1
    assert [item.message for item in caplog.records] == ["traffic_log_queue_dropped_oldest"]


def test_queue_drains_at_most_1000_records() -> None:
    queue = TrafficLogQueue(max_entries=1100, max_bytes=10_000_000)
    for index in range(1001):
        queue.append(record(path=f"/{index}"))

    batch = queue.drain_batch()

    assert batch is not None
    assert len(batch.records) == 1000
    assert len(queue) == 1


def test_emitter_flushes_when_entry_threshold_is_reached() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"accepted": 2, "deduplicated": False})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            queue = TrafficLogQueue(max_entries=10, max_bytes=10_000)
            client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest", http=http)
            emitter = TrafficLogEmitter(queue=queue, client=client, max_batch_entries=2)
            emitter.enqueue(record(path="/one"))
            emitter.enqueue(record(path="/two"))
            assert emitter.should_flush() is True
            await run_traffic_log_emitter_loop(emitter, max_iterations=1)
            stats = emitter.stats()
            assert stats.submitted_batches == 1
            assert stats.submitted_records == 2
            assert stats.queued_records == 0

    asyncio.run(run())

    assert len(requests) == 1
    body = json.loads(requests[0].content)
    assert [item["path"] for item in body["logs"]] == ["/one", "/two"]


def test_traffic_log_client_retries_with_same_idempotency_key() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, json={"error": "rate limited"})
        return httpx.Response(200, json={"accepted": 1, "deduplicated": False})

    async def no_sleep(delay: float) -> None:
        assert delay == 0.5

    async def run() -> dict[str, object]:
        batch = TrafficLogBatch.create([record()])
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest", http=http)
            return await client.submit_with_retries(batch, sleep=no_sleep)

    result = asyncio.run(run())

    assert result == {"accepted": 1, "deduplicated": False}
    assert len(requests) == 2
    assert requests[0].headers["authorization"] == "Bearer ingest"
    assert requests[0].url == "https://console.example.com/internal/traffic-logs"
    first_body = json.loads(requests[0].content)
    second_body = json.loads(requests[1].content)
    assert first_body["idempotency_key"] == second_body["idempotency_key"]
    assert first_body["logs"][0]["path"] == "/repos"


def test_emitter_retains_retryable_failed_batch_with_same_idempotency_key() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(503, json={"error": "unavailable"})
        return httpx.Response(200, json={"accepted": 1, "deduplicated": False})

    async def run() -> TrafficLogEmitter:
        async def no_sleep(delay: float) -> None:
            assert delay >= 0

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            queue = TrafficLogQueue(max_entries=10, max_bytes=10_000)
            client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest", http=http)
            emitter = TrafficLogEmitter(queue=queue, client=client, max_submit_attempts=1)
            emitter.enqueue(record())
            assert await emitter.flush_once(sleep=no_sleep) is False
            assert emitter.stats().pending_records == 1
            assert await emitter.flush_once(sleep=no_sleep) is True
            return emitter

    emitter = asyncio.run(run())

    assert len(requests) == 2
    first_body = json.loads(requests[0].content)
    second_body = json.loads(requests[1].content)
    assert first_body["idempotency_key"] == second_body["idempotency_key"]
    stats = emitter.stats()
    assert stats.failed_attempts == 1
    assert stats.pending_records == 0
    assert stats.submitted_records == 1


def test_emitter_drops_unretryable_failed_batch_and_continues() -> None:
    responses = [400, 200]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(responses.pop(0), json={"accepted": 1})

    async def run() -> TrafficLogEmitter:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            queue = TrafficLogQueue(max_entries=10, max_bytes=10_000)
            client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest", http=http)
            emitter = TrafficLogEmitter(queue=queue, client=client, max_submit_attempts=1)
            emitter.enqueue(record(path="/bad"))
            assert await emitter.flush_once() is False
            emitter.enqueue(record(path="/next"))
            assert await emitter.flush_once() is True
            return emitter

    emitter = asyncio.run(run())

    assert len(requests) == 2
    first_body = json.loads(requests[0].content)
    second_body = json.loads(requests[1].content)
    assert first_body["idempotency_key"] != second_body["idempotency_key"]
    assert first_body["logs"][0]["path"] == "/bad"
    assert second_body["logs"][0]["path"] == "/next"
    stats = emitter.stats()
    assert stats.dropped_unretryable_batches == 1
    assert stats.dropped_unretryable_records == 1
    assert stats.submitted_records == 1
