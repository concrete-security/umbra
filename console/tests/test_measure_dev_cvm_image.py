"""Regression coverage for the Dev image measurement operator script."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "ops" / "deploy" / "measure-dev-cvm-image.py"
SPEC = importlib.util.spec_from_file_location("measure_dev_cvm_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
measure_dev_cvm_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure_dev_cvm_image)


@pytest.mark.parametrize(
    ("failure_point", "expected_stderr"),
    [
        ("measure", "measure-dev-cvm-image: failed; detailed diagnostics were suppressed\n"),
        ("write", "measure-dev-cvm-image: failed; detailed diagnostics were suppressed\n"),
        ("shade", "measure-dev-cvm-image: shade SHADE_FAILED\n"),
        ("phala", "measure-dev-cvm-image: phala PHALA_FAILED\n"),
    ],
    ids=["measure", "manifest-write", "shade", "phala"],
)
def test_main_details_redaction_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_point: str,
    expected_stderr: str,
) -> None:
    """Provider values and private paths never enter retained stderr."""

    secret = "must-not-appear-in-public-logs"
    args = argparse.Namespace(output=f"/private/{secret}.json")

    async def fake_measure(_args: argparse.Namespace) -> dict[str, str]:
        if failure_point == "measure":
            raise RuntimeError(secret)
        if failure_point == "shade":
            raise measure_dev_cvm_image.ShadeError("SHADE_FAILED", output=f"path: /private/{secret}")
        if failure_point == "phala":
            raise measure_dev_cvm_image.PhalaError(
                "PHALA_FAILED",
                output=f"SECURITY_CVM_PROXY_TOKEN: {secret}",
            )
        return {"image_ref": "registry.invalid/example@sha256:" + "a" * 64}

    def fake_write(_path: Path, _payload: str) -> None:
        raise OSError(secret)

    monkeypatch.setattr(measure_dev_cvm_image, "parse_args", lambda: args)
    monkeypatch.setattr(measure_dev_cvm_image, "measure", fake_measure)
    if failure_point == "write":
        monkeypatch.setattr(measure_dev_cvm_image, "write_private_text", fake_write)

    assert measure_dev_cvm_image.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected_stderr
    assert secret not in captured.err
