import asyncio
from uuid import UUID

from concrete_console import scheduler


class FakeConn:
    def __init__(self, *, fetch_rows=None, execute_result="UPDATE 1"):
        self.fetch_rows = fetch_rows or []
        self.execute_result = execute_result
        self.fetch_calls: list[tuple[str, tuple[object, ...]]] = []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return self.fetch_rows

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return self.execute_result


def operation_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000030"),
        "kind": "cvm.launch",
        "status": "pending",
        "progress_step": "persist_stub",
        "progress_percent": 10,
    }
    row.update(overrides)
    return row


def test_pending_operation_start_progress_advances_known_sagas() -> None:
    assert scheduler.pending_operation_start_progress(
        "cvm.launch",
        progress_step="persist_stub",
        progress_percent=10,
    ) == ("phala_deploy", 20)
    assert scheduler.pending_operation_start_progress(
        "security_cvm.provision",
        progress_step="persist_tokens_and_stub",
        progress_percent=10,
    ) == ("phala_deploy", 20)
    assert scheduler.pending_operation_start_progress(
        "cvm.terminate",
        progress_step="queued",
        progress_percent=0,
    ) == ("phala_terminate", 25)


def test_pending_operation_start_progress_ignores_unknown_kind() -> None:
    assert (
        scheduler.pending_operation_start_progress(
            "unknown.kind",
            progress_step="queued",
            progress_percent=0,
        )
        is None
    )


def test_claim_active_operations_uses_skip_locked() -> None:
    conn = FakeConn(fetch_rows=[operation_row()])

    rows = asyncio.run(scheduler.claim_active_operations(conn, batch_size=7))

    assert rows == [operation_row()]
    query, args = conn.fetch_calls[0]
    assert "FOR UPDATE SKIP LOCKED" in query
    assert "updated_at < now() - INTERVAL '30 seconds'" in query
    assert args == (7,)


def test_advance_claimed_operation_marks_pending_row_running() -> None:
    conn = FakeConn()

    advanced = asyncio.run(scheduler.advance_claimed_operation(conn, operation_row()))

    assert advanced is True
    query, args = conn.execute_calls[0]
    assert "SET status = 'running'" in query
    assert args == (
        UUID("00000000-0000-4000-8000-000000000030"),
        "phala_deploy",
        20,
    )


def test_advance_claimed_operation_leaves_running_row_unchanged() -> None:
    conn = FakeConn()

    advanced = asyncio.run(scheduler.advance_claimed_operation(conn, operation_row(status="running")))

    assert advanced is False
    assert conn.execute_calls == []
