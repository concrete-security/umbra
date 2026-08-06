#!/usr/bin/env python3
"""Reject mutable third-party GitHub Actions references."""

from __future__ import annotations

from pathlib import Path
from pathlib import PurePosixPath
import re
import sys

import yaml
from yaml.nodes import MappingNode
from yaml.nodes import Node
from yaml.nodes import ScalarNode
from yaml.nodes import SequenceNode


REPO_ROOT = Path(__file__).resolve().parent.parent
SHA_REF_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")
SLSA_REUSABLE_PATH = (
    "slsa-framework/slsa-github-generator/"
    ".github/workflows/generator_generic_slsa3.yml"
)
SLSA_REUSABLE_REF = f"{SLSA_REUSABLE_PATH}@v2.1.0"
SLSA_BUILDER_ID = (
    f"https://github.com/{SLSA_REUSABLE_PATH}@refs/tags/"
    f"{SLSA_REUSABLE_REF.rsplit('@', 1)[1]}"
)
SETUP_UV_ACTION = "astral-sh/setup-uv"
CACHE_ACTION = "actions/cache"
PR_CACHE_WORKFLOW = Path(".github/workflows/pr-gate.yml")
PR_CACHE_PATHS = (
    "~/.cargo/registry",
    "~/.cargo/git",
    "target",
    "~/.cache/uv",
)
PR_CACHE_KEYS = {
    "check": (
        "pr-gate-${{ runner.os }}-${{ hashFiles('.python-version', 'Cargo.lock', "
        "'rust-toolchain.toml', 'console/uv.lock', 'cvms/security/uv.lock') }}"
    ),
    "test": (
        "pr-gate-test-${{ runner.os }}-${{ hashFiles('.python-version', "
        "'Cargo.lock', 'rust-toolchain.toml', 'console/uv.lock', "
        "'cvms/security/uv.lock') }}"
    ),
}
SLSA_BUILDER_PIN_PATTERNS = (
    (
        Path("cli/src/commands/update.rs"),
        re.compile(
            r'^\s*const\s+SLSA_BUILDER_ID\s*:\s*&str\s*=\s*"(?P<value>[^"]+)"\s*;\s*$',
            re.MULTILINE,
        ),
    ),
    (
        Path("ops/installer/install.sh"),
        re.compile(
            r'''^\s*slsa_builder_id=(?P<quote>['"])(?P<value>[^'"]+)(?P=quote)\s*$''',
            re.MULTILINE,
        ),
    ),
    (
        Path("ops/cli-release/verify-cli-release-artifact.sh"),
        re.compile(
            r'''^\s*builder_id=(?P<quote>['"])(?P<value>[^'"]+)(?P=quote)\s*$''',
            re.MULTILINE,
        ),
    ),
)


def action_reference_nodes(source: str) -> list[tuple[int, str]]:
    """Parse YAML and return every structurally resolved `uses` scalar."""
    try:
        documents = list(yaml.compose_all(source, Loader=yaml.BaseLoader))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f"line {mark.line + 1}: " if mark is not None else ""
        raise ValueError(f"{location}invalid YAML: {exc}") from exc

    references: list[tuple[int, str]] = []
    visited: set[int] = set()

    def walk(node: Node | None) -> None:
        if node is None or id(node) in visited:
            return
        visited.add(id(node))
        if isinstance(node, MappingNode):
            for key, value in node.value:
                if isinstance(key, ScalarNode) and key.value == "uses":
                    line_number = key.start_mark.line + 1
                    if not isinstance(value, ScalarNode) or not value.value:
                        raise ValueError(
                            f"line {line_number}: uses key must have a non-empty "
                            "scalar value"
                        )
                    references.append((line_number, value.value))
                walk(key)
                walk(value)
        elif isinstance(node, SequenceNode):
            for value in node.value:
                walk(value)

    for document in documents:
        walk(document)
    return references


def action_references(source: str) -> list[str]:
    """Return resolved action references from YAML source for focused tests."""
    return [reference for _, reference in action_reference_nodes(source)]


def action_files(root: Path = REPO_ROOT) -> list[Path]:
    """Return workflows plus any repository-local composite action manifests."""
    workflows = (root / ".github/workflows").glob("*.y*ml")
    composites = (root / ".github/actions").rglob("*.y*ml")
    return sorted({*workflows, *composites})


def workflow_cache_policy_failures(root: Path = REPO_ROOT) -> list[str]:
    """Keep pull-request caches exact and disable setup actions' implicit cache."""
    failures: list[str] = []
    seen_pr_caches: set[str] = set()
    workflow_root = root / ".github/workflows"

    for workflow_path in sorted(workflow_root.glob("*.y*ml")):
        relative_path = workflow_path.relative_to(root)
        try:
            workflow = yaml.load(
                workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
            )
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            failures.append(f"{relative_path}: cannot inspect cache policy: {exc}")
            continue
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            failures.append(f"{relative_path}: workflow jobs must be a mapping")
            continue

        for job_name, job in workflow["jobs"].items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                failures.append(f"{relative_path}: job {job_name} steps must be a list")
                continue
            for step_index, step in enumerate(steps, start=1):
                if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
                    continue
                action = step["uses"].partition("@")[0]
                inputs = step.get("with", {})
                location = f"{relative_path}: job {job_name} step {step_index}"
                if action == SETUP_UV_ACTION:
                    if not isinstance(inputs, dict) or inputs.get("enable-cache") != "false":
                        failures.append(
                            f"{location}: setup-uv implicit cache must be explicitly disabled"
                        )
                    continue
                if action != CACHE_ACTION:
                    continue
                if relative_path != PR_CACHE_WORKFLOW or job_name not in PR_CACHE_KEYS:
                    failures.append(
                        f"{location}: cache action is outside the reviewed PR cache policy"
                    )
                    continue
                if job_name in seen_pr_caches:
                    failures.append(f"{location}: duplicate cache action for reviewed job")
                    continue
                seen_pr_caches.add(job_name)
                if not isinstance(inputs, dict):
                    failures.append(f"{location}: cache inputs must be a mapping")
                    continue
                if set(inputs) != {"path", "key"}:
                    failures.append(
                        f"{location}: cache inputs must contain only exact path and key values"
                    )
                paths = tuple(
                    line.strip()
                    for line in str(inputs.get("path", "")).splitlines()
                    if line.strip()
                )
                if paths != PR_CACHE_PATHS:
                    failures.append(f"{location}: cached paths differ from reviewed public paths")
                if inputs.get("key") != PR_CACHE_KEYS[job_name]:
                    failures.append(f"{location}: cache key differs from the exact lock-bound key")

    missing = set(PR_CACHE_KEYS) - seen_pr_caches
    for job_name in sorted(missing):
        failures.append(
            f"{PR_CACHE_WORKFLOW}: missing reviewed cache action for job {job_name}"
        )
    return failures


def local_reference_parts(reference: str) -> tuple[str, ...] | None:
    """Return a normalized repository-local reference or reject traversal."""
    if not reference.startswith("./") or "@" in reference or "\\" in reference:
        return None
    raw_parts = reference[2:].split("/")
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        return None
    normalized = PurePosixPath(*raw_parts)
    if normalized.is_absolute() or ".." in normalized.parts:
        return None
    return normalized.parts


def local_reference_manifest(root: Path, reference: str) -> tuple[Path | None, str | None]:
    """Resolve a local action/workflow to the YAML file the checker must scan."""
    parts = local_reference_parts(reference)
    if parts is None:
        return None, "local Actions reference is malformed or escapes the repository"

    resolved_root = root.resolve()
    target = root.joinpath(*parts)
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(resolved_root):
        return None, "local Actions reference resolves outside the repository"
    if target.is_file():
        if target.suffix not in {".yml", ".yaml"}:
            return None, "local reusable workflow must be a YAML file"
        return target, None
    if not target.is_dir():
        return None, "local action or reusable workflow does not exist"

    manifests = [
        candidate
        for candidate in (target / "action.yml", target / "action.yaml")
        if candidate.is_file()
    ]
    if len(manifests) != 1:
        return None, "local action directory must contain exactly one action manifest"
    return manifests[0], None


def reference_allowed(reference: str) -> bool:
    """Allow local actions, commit SHAs, and only the exact reviewed SLSA tag."""
    referenced_path = reference.partition("@")[0]
    if referenced_path == SLSA_REUSABLE_PATH:
        return reference == SLSA_REUSABLE_REF
    return (
        local_reference_parts(reference) is not None
        or SHA_REF_RE.fullmatch(reference) is not None
    )


def action_reference_failures(root: Path = REPO_ROOT) -> list[str]:
    """Return mutable, malformed, or missing SLSA workflow reference findings."""
    failures: list[str] = []
    slsa_references: list[str] = []
    files = action_files(root)
    if not files:
        return ["no GitHub Actions workflow or composite-action manifests found"]

    visited: set[Path] = set()
    resolved_root = root.resolve()
    next_file = 0
    while next_file < len(files):
        action_file = files[next_file]
        next_file += 1
        resolved_file = action_file.resolve()
        if not resolved_file.is_relative_to(resolved_root):
            failures.append(
                f"{action_file.relative_to(root)}: action manifest resolves outside "
                "the repository"
            )
            continue
        if resolved_file in visited:
            continue
        visited.add(resolved_file)
        display_path = action_file.relative_to(root)
        try:
            references = action_reference_nodes(
                action_file.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, ValueError) as exc:
            failures.append(f"{display_path}: {exc}")
            continue
        for line_number, reference in references:
            if reference.startswith("./"):
                local_manifest, local_error = local_reference_manifest(root, reference)
                if local_error is not None:
                    failures.append(
                        f"{display_path}:{line_number}: {local_error}: {reference}"
                    )
                elif local_manifest is not None:
                    files.append(local_manifest)
            if reference.partition("@")[0] == SLSA_REUSABLE_PATH:
                slsa_references.append(reference)
            if reference_allowed(reference):
                continue
            failures.append(
                f"{display_path}:{line_number}: mutable Actions reference {reference}"
            )

    if slsa_references != [SLSA_REUSABLE_REF]:
        rendered = ", ".join(slsa_references) if slsa_references else "none"
        failures.append(
            "SLSA provenance workflow must have exactly one reference to "
            f"{SLSA_REUSABLE_REF}; found: {rendered}"
        )
    return failures


def slsa_builder_pin_failures(root: Path = REPO_ROOT) -> list[str]:
    """Keep updater and installer builder identities aligned with the workflow."""
    failures: list[str] = []
    for relative_path, pattern in SLSA_BUILDER_PIN_PATTERNS:
        path = root / relative_path
        if not path.is_file():
            failures.append(f"{relative_path}: missing SLSA builder-ID source")
            continue
        matches = list(pattern.finditer(path.read_text(encoding="utf-8")))
        if len(matches) != 1:
            failures.append(
                f"{relative_path}: expected exactly one SLSA builder-ID assignment; "
                f"found {len(matches)}"
            )
            continue
        actual = matches[0].group("value")
        if actual != SLSA_BUILDER_ID:
            failures.append(
                f"{relative_path}: SLSA builder ID {actual!r} does not match "
                f"{SLSA_BUILDER_ID!r}"
            )
    return failures


def main() -> int:
    """Allow only local, SHA, or the exact coordinated SLSA workflow ref."""
    failures = action_reference_failures()
    failures.extend(slsa_builder_pin_failures())
    failures.extend(workflow_cache_policy_failures())

    if failures:
        print("GitHub Actions pin check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        "GitHub Actions references are immutable "
        f"(exact SLSA exception: {SLSA_REUSABLE_REF})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
