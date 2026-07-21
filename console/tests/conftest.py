"""Shared pytest fixtures and a Phala fake for the Console test suite.

`FakePhalaClient` stands in for the real `PhalaClient` and is wrapped by the REAL
`CvmProvider`, so tests exercise the actual provider layer (including the
`PhalaError -> CvmProviderError` translation) instead of shortcutting it. It
implements only the methods the current (instance-type catalog) tests exercise;
a follow-up PR that migrates the scheduler/routes/cleanup tests onto this fake
will add the remaining `PhalaClient` methods (deploy/update/lifecycle) as those
tests actually need them.

The `phala_client` fixture is auto-injected (no import). `FakePhalaClient` and the
plain helpers (`PROVIDER_TYPES`, `unreachable`, `schema_drift`, `not_configured`)
are imported explicitly: `from conftest import ...`.
"""

import os
from pathlib import Path
import shutil

import pytest

from concrete_console.tee_provider.phala import PhalaClient, PhalaError

# Sample provider output (CPU types) FakePhalaClient returns on a successful fetch.
PROVIDER_TYPES = [
    {"name": "tdx.small", "family": "cpu", "vcpu": 1, "memory_gb": 2, "hourly_rate": 0.058, "currency": "USD"},
    {"name": "tdx.large", "family": "cpu", "vcpu": 4, "memory_gb": 8, "hourly_rate": 0.232, "currency": "USD"},
]


class FakePhalaClient:
    """In-memory stand-in for `PhalaClient` (only the methods the catalog tests
    use), wrapped by the real `CvmProvider`. `list_instance_types()` returns the
    next scripted outcome from `instance_types_outcomes` — a list is returned, a
    `PhalaError` is raised (the real CvmProvider then wraps it into
    `CvmProviderError`, as in production). An empty queue yields a default
    catalog, so a fresh fake behaves like a live provider."""

    def __init__(self) -> None:
        self.instance_types_outcomes: list = []
        self.default_instance_types: list = list(PROVIDER_TYPES)

    @classmethod
    def from_settings(cls, *, timeout_seconds=None) -> "FakePhalaClient":
        return cls()

    async def list_instance_types(self) -> list[dict]:
        if not self.instance_types_outcomes:
            return list(self.default_instance_types)
        outcome = self.instance_types_outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def unreachable() -> PhalaError:
    """A provider outage -> catalog kind `provider_unreachable`."""
    return PhalaError("cli_timeout")


def schema_drift(field: str = "items") -> PhalaError:
    """An unparseable provider response -> catalog kind `schema_drift` with a locus."""
    return PhalaError("instance_types_schema_drift", field=field)


def not_configured() -> PhalaError:
    """A missing provider token -> the configuration-state branch (daily cadence, WARNING)."""
    return PhalaError("not_configured")


REPO_ROOT = Path(__file__).resolve().parents[2]


def env_or_dotenv(name: str) -> str:
    """Look a variable up in the environment, falling back to the repo-root .env.

    The app itself only ever reads os.environ (config.load_settings does
    `dict(os.environ)`), so tests do too. This is a convenience for the live-Phala
    run: if you haven't exported the variable, we read it from the repo-root .env --
    exactly what docker/your shell would have loaded into the environment anyway --
    so you don't have to source it by hand. Returns "" when found nowhere.
    """
    value = os.environ.get(name, "").strip()
    if value:
        return value

    dotenv = REPO_ROOT / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{name}="):
                return line[len(name) + 1 :].strip().strip('"').strip("'")
    return ""


@pytest.fixture(params=["fake", "real"])
def phala_client(request, monkeypatch):
    """Provider-CONTRACT fixture, parametrized over the fake and the live Phala: a
    test that takes `phala_client` runs once per backend (`request.param` is
    "fake" or "real"). Both expose the same `PhalaClient` surface, so the test
    needs no branching. The 'real' backend needs `PHALA_API_TOKEN` (exported, or in
    the repo-root .env) and the installed `phala` CLI, and is skipped otherwise.

    USE FOR READ-ONLY CONTRACT TESTS ONLY (e.g. `list_instance_types`). The
    mutating methods hit real infrastructure and would create or destroy real
    CVMs — never exercise those against the live provider. Lifecycle tests that
    script provider outcomes stay on the `service` fixture: you cannot script a
    live provider.
    """
    if request.param == "real":
        token = env_or_dotenv("PHALA_API_TOKEN")
        if not token:
            pytest.skip("PHALA_API_TOKEN not set (env or repo-root .env); skipping the live-Phala run")
        # Push it into the environment so PhalaClient.from_settings (which reads
        # os.environ) picks it up; monkeypatch reverts it after the test.
        monkeypatch.setenv("PHALA_API_TOKEN", token)
        client = PhalaClient.from_settings(timeout_seconds=30.0)
        if not (Path(client.cli_path).exists() or shutil.which(client.cli_path)):
            pytest.skip(f"phala CLI not installed at {client.cli_path!r}")
        return client
    return FakePhalaClient()
