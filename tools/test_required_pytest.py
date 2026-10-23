"""The mandatory test runner cannot turn missing coverage into a green gate."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


RUNNER = Path(__file__).resolve().parents[1] / "ops/verify/run-required-pytest.py"


def _run_suite(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "test_example.py").write_text(source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(RUNNER), "-q", "--confcutdir", str(tmp_path), str(tmp_path)],
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        capture_output=True,
        text=True,
        check=False,
    )


def test_required_pytest_passing_suite_success(tmp_path: Path) -> None:
    """A required suite succeeds when every test passes."""
    result = _run_suite(tmp_path, "def test_example():\n    assert True\n")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import pytest\npytest.skip('missing dependency', allow_module_level=True)\n", id="collection-skip"),
        pytest.param("import pytest\ndef test_example():\n    pytest.skip('missing dependency')\n", id="test-skip"),
        pytest.param("import pytest\n@pytest.mark.xfail\ndef test_example():\n    assert False\n", id="expected-failure"),
        pytest.param("import pytest\n@pytest.mark.xfail\ndef test_example():\n    assert True\n", id="unexpected-pass"),
        pytest.param("def test_example():\n    assert False\n", id="assertion-failure"),
        pytest.param("# no tests\n", id="empty-suite"),
    ],
)
def test_required_pytest_incomplete_suite_failure(tmp_path: Path, source: str) -> None:
    """Skipped, expected-failure, failing, or empty suites fail the required gate."""
    result = _run_suite(tmp_path, source)
    assert result.returncode != 0, result.stdout + result.stderr
