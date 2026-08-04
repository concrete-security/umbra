from __future__ import annotations

import asyncio
from io import StringIO

import pytest

from umbra_console.cleanup_phala import PhalaCleanupError, delete_managed_cvms


class FakePhalaClient:
    def __init__(self, rows):
        self.rows = rows
        self.deleted: list[str] = []

    async def list(self):
        return self.rows

    async def delete(self, app_id: str) -> None:
        self.deleted.append(app_id)


def run(awaitable):
    return asyncio.run(awaitable)


def test_delete_managed_cvms_deletes_only_managed_prefix_rows() -> None:
    client = FakePhalaClient(
        [
            {"name": "umbra-v0-cvm-owned", "id": "app-1"},
            {"name": "teammate-prod", "id": "app-2"},
            {"cvmName": "umbra-v0-sc-owned", "app_id": "app-3"},
        ]
    )
    output = StringIO()

    summary = run(delete_managed_cvms(client, out=output))

    assert summary.deleted == 2
    assert client.deleted == ["app-1", "app-3"]
    assert "teammate-prod" not in output.getvalue()
    assert "umbra-v0-cvm-owned" in output.getvalue()


def test_delete_managed_cvms_reports_empty_scope() -> None:
    client = FakePhalaClient([])
    output = StringIO()

    summary = run(delete_managed_cvms(client, out=output))

    assert summary.deleted == 0
    assert client.deleted == []
    assert "no umbra-v0 Phala CVMs found" in output.getvalue()


def test_delete_managed_cvms_requires_app_id_for_owned_rows() -> None:
    client = FakePhalaClient([{"name": "umbra-v0-cvm-owned"}])

    with pytest.raises(PhalaCleanupError):
        run(delete_managed_cvms(client))
