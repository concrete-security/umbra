#!/usr/bin/env python3
"""Run a mandatory pytest suite: skipped and expected-failure tests fail the gate."""

from __future__ import annotations

import sys

import pytest


class RequiredTests:
    def __init__(self) -> None:
        self.skipped: set[str] = set()

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if report.skipped:
            self.skipped.add(report.nodeid)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped or hasattr(report, "wasxfail"):
            self.skipped.add(report.nodeid)

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        if self.skipped and exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter: object) -> None:
        if self.skipped:
            terminalreporter.write_sep(
                "=", "Required suite failed: skips and expected failures are forbidden", red=True
            )


if __name__ == "__main__":
    raise SystemExit(pytest.main(sys.argv[1:], plugins=[RequiredTests()]))
