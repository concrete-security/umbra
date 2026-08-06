"""Tests for the fail-closed GitHub Actions reference checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


CHECKER_PATH = Path(__file__).with_name("check-github-actions.py")
SPEC = importlib.util.spec_from_file_location("check_github_actions", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

PINNED_ACTION = f"actions/checkout@{'a' * 40}"


@pytest.mark.parametrize(
    ("line", "reference"),
    [
        pytest.param(
            "uses: actions/checkout@main",
            "actions/checkout@main",
            id="plain-block-key",
        ),
        pytest.param(
            '"uses": "actions/checkout@v4"',
            "actions/checkout@v4",
            id="double-quoted-block-key",
        ),
        pytest.param(
            "- 'uses' : 'actions/checkout@main'",
            "actions/checkout@main",
            id="single-quoted-sequence-key",
        ),
        pytest.param(
            '{name: checkout, "uses": actions/checkout@main}',
            "actions/checkout@main",
            id="quoted-flow-key",
        ),
        pytest.param(
            r'"\u0075ses": actions/checkout@main',
            "actions/checkout@main",
            id="escaped-double-quoted-key",
        ),
        pytest.param(
            "? 'uses': actions/checkout@main",
            "actions/checkout@main",
            id="explicit-mapping-key",
        ),
    ],
)
def test_action_references_quoted_key_success(line: str, reference: str) -> None:
    """All YAML spellings of the uses key expose their reference to policy."""

    assert checker.action_references(line) == [reference]


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("# uses: actions/checkout@main", id="comment"),
        pytest.param(
            "run: 'echo \"uses: actions/checkout@main\"'", id="run-string"
        ),
        pytest.param("name: 'uses: actions/checkout@main'", id="scalar-string"),
    ],
)
def test_action_references_non_key_success(line: str) -> None:
    """Text that merely contains uses syntax is not treated as an action key."""

    assert checker.action_references(line) == []


def test_action_references_missing_value_failure() -> None:
    """A uses key without a same-line scalar cannot bypass the checker."""

    with pytest.raises(ValueError, match="non-empty scalar value"):
        checker.action_references("uses: # hidden or multiline value")


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param("./.github/actions/local", id="local-action"),
        pytest.param(PINNED_ACTION, id="commit-sha"),
        pytest.param(checker.SLSA_REUSABLE_REF, id="exact-slsa-tag"),
    ],
)
def test_reference_allowed_immutable_success(reference: str) -> None:
    """Only local, commit-pinned, and the exact reviewed SLSA refs pass."""

    assert checker.reference_allowed(reference)


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param("actions/checkout@main", id="branch"),
        pytest.param("actions/checkout@v4", id="major-tag"),
        pytest.param(
            checker.SLSA_REUSABLE_REF.replace("@v2.1.0", "@v2.1.1"),
            id="slsa-version-drift",
        ),
        pytest.param(
            f"{checker.SLSA_REUSABLE_PATH}@{'b' * 40}",
            id="slsa-sha-invalid-for-generator",
        ),
        pytest.param(
            checker.SLSA_REUSABLE_REF.replace(
                "generator_generic_slsa3.yml", "generator_container_slsa3.yml"
            ),
            id="slsa-workflow-drift",
        ),
        pytest.param("./../outside", id="local-path-traversal"),
        pytest.param("./nested/../../outside", id="nested-local-path-traversal"),
    ],
)
def test_reference_allowed_mutable_failure(reference: str) -> None:
    """Mutable actions and every SLSA exception drift remain blocked."""

    assert not checker.reference_allowed(reference)


def test_action_reference_failures_quoted_key_failure(tmp_path: Path) -> None:
    """A hostile quoted uses key is reported by the repository-level check."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        "    steps:\n"
        '      - "uses": actions/checkout@main\n',
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


@pytest.mark.parametrize(
    "hostile_key",
    [
        pytest.param("*uses-key", id="alias"),
        pytest.param("&u uses", id="anchor"),
        pytest.param("!!str uses", id="short-tag"),
        pytest.param("!<tag:yaml.org,2002:str> uses", id="verbatim-tag"),
    ],
)
def test_action_reference_failures_node_property_failure(
    tmp_path: Path, hostile_key: str
) -> None:
    """YAML node properties cannot hide a mutable action behind a resolved key."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "x-key: &uses-key uses\n"
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        "    steps:\n"
        f"      - {hostile_key}: actions/checkout@main\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


@pytest.mark.parametrize(
    "hostile_step",
    [
        pytest.param("[*uses-key: actions/checkout@main]", id="flow-alias"),
        pytest.param("[!!str uses: actions/checkout@main]", id="flow-tag"),
        pytest.param("[&u uses: actions/checkout@main]", id="flow-anchor"),
        pytest.param("[{!!str uses: actions/checkout@main}]", id="nested-flow-tag"),
    ],
)
def test_action_reference_failures_embedded_node_property_failure(
    tmp_path: Path, hostile_step: str
) -> None:
    """Embedded flow collections cannot hide action keys with node properties."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "x-key: &uses-key uses\n"
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        f"    steps: {hostile_step}\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


def test_action_reference_failures_embedded_explicit_key_failure(
    tmp_path: Path,
) -> None:
    """A split explicit key inside a flow mapping is rejected fail closed."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        "    steps:\n"
        "      - { ? uses\n"
        "          : actions/checkout@main }\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


@pytest.mark.parametrize(
    "hostile_name",
    [
        pytest.param('name: "foo: |\n      continuation"', id="block-indicator"),
        pytest.param('name: "foo\n      #not-a-comment"', id="hash-continuation"),
        pytest.param("name: 'foo: >\n      continuation'", id="single-quoted"),
    ],
)
def test_action_reference_failures_multiline_quote_failure(
    tmp_path: Path, hostile_name: str
) -> None:
    """Multiline quoted scalars cannot hide a later mutable action reference."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs: {\n"
        "  provenance: { uses: "
        f"{checker.SLSA_REUSABLE_REF} }},\n"
        "  hostile: {\n"
        f"    {hostile_name}\n"
        "      , steps: [ { uses: actions/checkout@main } ]\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


@pytest.mark.parametrize(
    "hostile_step",
    [
        pytest.param(
            "[{name: it's, uses: actions/checkout@main, note: that's}]",
            id="plain-apostrophes",
        ),
        pytest.param(
            '[{name: say"hi, uses: actions/checkout@main, note: bye"now}]',
            id="plain-double-quotes",
        ),
    ],
)
def test_action_reference_failures_plain_quote_failure(
    tmp_path: Path, hostile_step: str
) -> None:
    """Quote bytes in plain scalars cannot mask a structural uses key."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        f"    steps: {hostile_step}\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


def test_action_reference_failures_missing_slsa_failure(tmp_path: Path) -> None:
    """Removing the provenance workflow cannot silently satisfy the pin check."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "ordinary.yml").write_text(
        f"steps:\n  - uses: {PINNED_ACTION}\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("must have exactly one reference" in item for item in failures)


def test_action_reference_failures_local_manifest_failure(tmp_path: Path) -> None:
    """A referenced local action outside .github/actions is recursively checked."""

    workflows = tmp_path / ".github/workflows"
    local_action = tmp_path / "ops/action"
    workflows.mkdir(parents=True)
    local_action.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        "    steps:\n"
        "      - uses: ./ops/action\n",
        encoding="utf-8",
    )
    (local_action / "action.yml").write_text(
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/checkout@main\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("ops/action/action.yml" in item for item in failures)
    assert any("mutable Actions reference actions/checkout@main" in item for item in failures)


def test_action_reference_failures_local_escape_failure(tmp_path: Path) -> None:
    """A repository-local reference cannot traverse above the checkout root."""

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "hostile.yml").write_text(
        "jobs:\n"
        "  provenance:\n"
        f"    uses: {checker.SLSA_REUSABLE_REF}\n"
        "  hostile:\n"
        "    steps:\n"
        "      - uses: ./../outside\n",
        encoding="utf-8",
    )

    failures = checker.action_reference_failures(tmp_path)

    assert any("escapes the repository" in item for item in failures)


def test_action_reference_failures_manifest_symlink_failure(tmp_path: Path) -> None:
    """A workflow symlink cannot make the checker read outside the repository."""

    root = tmp_path / "repo"
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True)
    outside = tmp_path / "outside.yml"
    outside.write_text(
        f"jobs: {{provenance: {{uses: {checker.SLSA_REUSABLE_REF}}}}}\n",
        encoding="utf-8",
    )
    (workflows / "outside.yml").symlink_to(outside)

    failures = checker.action_reference_failures(root)

    assert any("manifest resolves outside the repository" in item for item in failures)


@pytest.mark.parametrize(
    ("rust_pin", "shell_pin", "artifact_pin", "drift_path"),
    [
        pytest.param(
            checker.SLSA_BUILDER_ID.replace("v2.1.0", "v2.1.1"),
            checker.SLSA_BUILDER_ID,
            checker.SLSA_BUILDER_ID,
            "cli/src/commands/update.rs",
            id="updater-drift",
        ),
        pytest.param(
            checker.SLSA_BUILDER_ID,
            checker.SLSA_BUILDER_ID.replace("v2.1.0", "v2.1.1"),
            checker.SLSA_BUILDER_ID,
            "ops/installer/install.sh",
            id="installer-drift",
        ),
        pytest.param(
            checker.SLSA_BUILDER_ID,
            checker.SLSA_BUILDER_ID,
            checker.SLSA_BUILDER_ID.replace("v2.1.0", "v2.1.1"),
            "ops/cli-release/verify-cli-release-artifact.sh",
            id="artifact-verifier-drift",
        ),
    ],
)
def test_slsa_builder_pin_drift_failure(
    tmp_path: Path,
    rust_pin: str,
    shell_pin: str,
    artifact_pin: str,
    drift_path: str,
) -> None:
    """Updater and installer builder identities cannot drift from the workflow."""

    updater = tmp_path / "cli/src/commands"
    installer = tmp_path / "ops/installer"
    artifact_verifier = tmp_path / "ops/cli-release"
    updater.mkdir(parents=True)
    installer.mkdir(parents=True)
    artifact_verifier.mkdir(parents=True)
    (updater / "update.rs").write_text(
        f'const SLSA_BUILDER_ID: &str = "{rust_pin}";\n', encoding="utf-8"
    )
    (installer / "install.sh").write_text(
        f'slsa_builder_id="{shell_pin}"\n', encoding="utf-8"
    )
    (artifact_verifier / "verify-cli-release-artifact.sh").write_text(
        f'builder_id="{artifact_pin}"\n', encoding="utf-8"
    )

    failures = checker.slsa_builder_pin_failures(tmp_path)

    assert any(item.startswith(drift_path) for item in failures)


def test_repository_action_references_success() -> None:
    """The checked-in workflows contain only the coordinated immutable refs."""

    assert checker.action_reference_failures(checker.REPO_ROOT) == []


def test_repository_slsa_builder_pins_success() -> None:
    """The updater and bootstrap installer use the reviewed workflow identity."""

    assert checker.slsa_builder_pin_failures(checker.REPO_ROOT) == []


def _write_cache_policy_workflow(root: Path, source: str) -> None:
    workflow = root / checker.PR_CACHE_WORKFLOW
    workflow.parent.mkdir(parents=True)
    workflow.write_text(source, encoding="utf-8")


def _cache_policy_workflow() -> str:
    paths = "\n".join(f"              {path}" for path in checker.PR_CACHE_PATHS)
    jobs = []
    for job_name, key in checker.PR_CACHE_KEYS.items():
        jobs.append(
            f"  {job_name}:\n"
            "    steps:\n"
            "      - uses: astral-sh/setup-uv@" + "a" * 40 + "\n"
            "        with:\n"
            "          enable-cache: 'false'\n"
            "      - uses: actions/cache@" + "b" * 40 + "\n"
            "        with:\n"
            "          path: |\n"
            f"{paths}\n"
            f"          key: {key}\n"
        )
    return "jobs:\n" + "".join(jobs)


def test_workflow_cache_policy_exact_success(tmp_path: Path) -> None:
    """Only the reviewed paths and lock-bound keys form the PR caches."""

    _write_cache_policy_workflow(tmp_path, _cache_policy_workflow())

    assert checker.workflow_cache_policy_failures(tmp_path) == []


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        pytest.param(
            "enable-cache: 'false'",
            "enable-cache: 'true'",
            "implicit cache",
            id="setup-uv-cache",
        ),
        pytest.param(
            "          key: pr-gate-${{ runner.os }}-",
            "          restore-keys: pr-gate-${{ runner.os }}-\n"
            "          key: pr-gate-${{ runner.os }}-",
            "only exact path and key",
            id="restore-prefix",
        ),
        pytest.param(
            "              target\n",
            "              target\n              .env\n",
            "reviewed public paths",
            id="secret-path",
        ),
        pytest.param(
            "hashFiles('.python-version', 'Cargo.lock'",
            "hashFiles('Cargo.lock'",
            "exact lock-bound key",
            id="missing-python-pin",
        ),
    ],
)
def test_workflow_cache_policy_drift_failure(
    tmp_path: Path, original: str, replacement: str, message: str
) -> None:
    """Implicit, fallback, secret-bearing, and under-keyed caches fail closed."""

    source = _cache_policy_workflow()
    assert original in source
    _write_cache_policy_workflow(tmp_path, source.replace(original, replacement, 1))

    assert any(
        message in failure
        for failure in checker.workflow_cache_policy_failures(tmp_path)
    )


def test_repository_workflow_cache_policy_success() -> None:
    """Checked-in workflows keep the cache trust boundary mechanically pinned."""

    assert checker.workflow_cache_policy_failures(checker.REPO_ROOT) == []
