from __future__ import annotations

import asyncio
from io import StringIO

import pytest

from umbra_console import cleanup_phala
from umbra_console.cleanup_phala import PhalaCleanupError, delete_managed_cvms
from umbra_console.tee_provider.phala import PhalaError


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


def test_delete_managed_cvms_scopes_deletions_success() -> None:
    """Only prefixed resources are deleted without replaying provider rows."""
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
    assert "umbra-v0-cvm-owned" not in output.getvalue()
    assert "deleted 2 Umbra-managed Phala CVM(s)" in output.getvalue()


def test_delete_managed_cvms_empty_scope_success() -> None:
    """An empty provider inventory is a successful, explicit no-op."""
    client = FakePhalaClient([])
    output = StringIO()

    summary = run(delete_managed_cvms(client, out=output))

    assert summary.deleted == 0
    assert client.deleted == []
    assert "no umbra-v0 Phala CVMs found" in output.getvalue()


def test_delete_managed_cvms_missing_app_id_failure() -> None:
    """A managed row without a validated identifier fails before deletion."""
    client = FakePhalaClient([{"name": "umbra-v0-cvm-owned"}])

    with pytest.raises(PhalaCleanupError):
        run(delete_managed_cvms(client))


def test_run_suppresses_provider_output_failure(monkeypatch, capsys) -> None:
    """Provider diagnostics never enter retained cleanup output on failure."""

    class FailingPhalaClient:
        async def list(self):
            raise PhalaError("fixture_failure", output="provider-secret-and-private-path")

    monkeypatch.setenv("PHALA_API_TOKEN", "fixture-token")
    monkeypatch.setattr(
        cleanup_phala.PhalaClient,
        "from_settings",
        classmethod(lambda cls: FailingPhalaClient()),
    )

    result = run(cleanup_phala.run())
    captured = capsys.readouterr()

    assert result == 1
    assert "fixture_failure" in captured.err
    assert "provider-secret-and-private-path" not in captured.err
