"""Tests for the crates.io keyword-policy checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


CHECKER_PATH = Path(__file__).with_name("check-cargo-keywords.py")
SPEC = importlib.util.spec_from_file_location("check_cargo_keywords", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def test_keyword_failures_valid_success() -> None:
    """Boundary-length keywords and every permitted separator pass."""

    assert checker.keyword_failures(
        {
            "name": "umbra-cli",
            "keywords": ["a" * 20, "developer_tools", "security-cli", "c+cli", "1"],
        }
    ) == []


@pytest.mark.parametrize(
    ("keywords", "expected"),
    [
        pytest.param(
            ["confidential-computing"],
            [
                "umbra-cli: keyword 'confidential-computing' has 22 characters; "
                "crates.io permits at most 20"
            ],
            id="oversized",
        ),
        pytest.param(
            ["one", "two", "three", "four", "five", "six"],
            ["umbra-cli: has 6 keywords; crates.io permits at most 5"],
            id="too-many",
        ),
        pytest.param(
            ["sécurité"],
            ["umbra-cli: keyword 'sécurité' must be ASCII"],
            id="non-ascii",
        ),
        pytest.param(
            ["bad keyword"],
            [
                "umbra-cli: keyword 'bad keyword' must start with an ASCII "
                "alphanumeric and contain only ASCII letters, numbers, _, -, or +"
            ],
            id="invalid-character",
        ),
        pytest.param(
            ["-security"],
            [
                "umbra-cli: keyword '-security' must start with an ASCII "
                "alphanumeric and contain only ASCII letters, numbers, _, -, or +"
            ],
            id="invalid-start",
        ),
        pytest.param(
            None,
            ["umbra-cli: keywords must be a list"],
            id="keywords-not-list",
        ),
        pytest.param(
            [1],
            ["umbra-cli: keyword values must be strings"],
            id="keyword-not-string",
        ),
    ],
)
def test_keyword_failures_invalid_failure(
    keywords: object, expected: list[str]
) -> None:
    """Every crates.io keyword constraint returns its exact failure."""

    assert checker.keyword_failures(
        {"name": "umbra-cli", "keywords": keywords}
    ) == expected


def test_publishable_keyword_failures_all_publishable_packages_failure() -> None:
    """All publishable packages are checked while unpublishable members are skipped."""

    metadata = {
        "packages": [
            {"name": "first", "publish": None, "keywords": ["x" * 21]},
            {"name": "second", "publish": ["crates-io"], "keywords": ["-invalid"]},
            {"name": "internal", "publish": [], "keywords": ["x" * 21]},
        ]
    }
    assert checker.publishable_keyword_failures(metadata) == [
        "first: keyword 'xxxxxxxxxxxxxxxxxxxxx' has 21 characters; "
        "crates.io permits at most 20",
        "second: keyword '-invalid' must start with an ASCII alphanumeric and "
        "contain only ASCII letters, numbers, _, -, or +",
    ]


def test_publishable_keyword_failures_invalid_metadata_failure() -> None:
    """Malformed Cargo metadata cannot silently bypass keyword validation."""

    with pytest.raises(ValueError, match="cargo metadata packages must be a list"):
        checker.publishable_keyword_failures({})
