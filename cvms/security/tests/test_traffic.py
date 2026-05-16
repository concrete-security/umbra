import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID

import httpx

from concrete_security_cvm.traffic import TrafficLogBatch, TrafficLogClient, TrafficLogQueue, TrafficLogRecord


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


def test_queue_drains_at_most_1000_records() -> None:
    queue = TrafficLogQueue(max_entries=1100, max_bytes=10_000_000)
    for index in range(1001):
        queue.append(record(path=f"/{index}"))

    batch = queue.drain_batch()

    assert batch is not None
    assert len(batch.records) == 1000
    assert len(queue) == 1


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
