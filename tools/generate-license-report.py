#!/usr/bin/env python3
"""Inventory third-party dependency licenses from the authoritative locks.

Reads the Cargo, uv, and npm locks that pin every distributed artifact's
dependency graph, resolves each package's declared license, and rewrites the
generated inventory sections of ``THIRD_PARTY_NOTICES.md`` in place.

This produces the reviewable notice artifact.  It is deliberately *not* a
second license policy: enforcement stays with the Trivy ``license`` scanner and
``.trivy-license-ignore.rego`` wired into ``.github/workflows/security.yml``.
The categories below only sort the inventory and surface anything a maintainer
must decide about, so no finding can be approved silently.

Requires network access: Python wheel metadata is not carried in ``uv.lock``,
so declared licenses come from the immutable PyPI metadata of the locked
version.  Cargo and npm licenses come from the locks/manifests themselves.

Usage:
    uv run --python "$(cat .python-version)" --no-project python \
        tools/generate-license-report.py           # rewrite the artifact
    ... tools/generate-license-report.py --check    # fail if it is stale
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "THIRD_PARTY_NOTICES.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED INVENTORY -->"
END_MARKER = "<!-- END GENERATED INVENTORY -->"

# Targets published by .github/workflows/publish-cli.yml. The CLI inventory is
# the union of their locked graphs so no shipped binary has an unlisted crate.
CLI_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
)
# The two in-image Rust binaries are Linux-only.
IMAGE_TARGET = "x86_64-unknown-linux-gnu"

PERMISSIVE = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "BSD-1-Clause",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "ISC",
        "MIT",
        "MIT-0",
        "MITNFA",
        "MPL-1.1",  # not reached today; listed so a hit is categorized, not silent
        "Python-2.0",
        "Unicode-3.0",
        "Unicode-DFS-2016",
        "Zlib",
    }
)
PUBLIC_DOMAIN = frozenset({"CC0-1.0", "Unlicense", "WTFPL"})
# Permissive but non-OSI / data-oriented: no copyleft, still worth naming.
NON_OSI_PERMISSIVE = frozenset({"CDLA-Permissive-2.0", "CC-BY-4.0", "CC-BY-3.0"})
WEAK_COPYLEFT = frozenset(
    {
        "EPL-2.0",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
    }
)
STRONG_COPYLEFT = frozenset(
    {
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "SSPL-1.0",
    }
)

# Non-SPDX spellings seen in package metadata, mapped to their SPDX identifier.
ALIASES = {
    "APACHE-2.0": "Apache-2.0",
    "APACHE 2.0": "Apache-2.0",
    "APACHE SOFTWARE LICENSE": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "BSD LICENSE": "BSD-3-Clause",
    "BSD-3": "BSD-3-Clause",
    "GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPLV3)": "LGPL-3.0-only",
    "LGPL V3": "LGPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "MIT LICENSE": "MIT",
    "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)": "MPL-2.0",
    "PSF-2.0": "Python-2.0",
    "THE UNLICENSE (UNLICENSE)": "Unlicense",
    "UNLICENSE": "Unlicense",
    "ZLIB": "Zlib",
}

# PyPI trove classifier -> SPDX identifier, for wheels that publish no
# `license_expression` and only a prose `license` field.
CLASSIFIERS = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": (
        "LGPL-3.0-only"
    ),
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later"
    " (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later"
    " (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "Python-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}

REVIEW_CATEGORIES = ("weak copyleft", "strong copyleft", "non-OSI permissive", "unknown")


class ReportError(RuntimeError):
    """The inventory could not be built from the reviewed inputs."""


def normalize(identifier: str) -> str:
    """Map one license spelling onto its SPDX identifier where recognized."""

    cleaned = identifier.strip().strip("()").strip()
    if cleaned.endswith("+") and f"{cleaned[:-1]}-or-later" in WEAK_COPYLEFT:
        return f"{cleaned[:-1]}-or-later"
    return ALIASES.get(cleaned.upper(), cleaned)


def split_expression(expression: str) -> list[list[str]]:
    """Split an SPDX expression into OR-alternatives of AND-ed identifiers."""

    # `/` is the legacy Cargo separator for a choice; `WITH` exceptions do not
    # change the category of the license they qualify. Operators must be
    # whitespace-delimited so identifiers such as `LGPL-2.1-or-later` survive.
    text = re.sub(r"\s+WITH\s+[\w.+-]+", "", expression, flags=re.IGNORECASE)
    text = text.replace("/", " OR ").replace("(", " ").replace(")", " ")
    alternatives = re.split(r"(?i)\s+OR\s+", text.strip())
    return [
        [
            normalize(part)
            for part in re.split(r"(?i)\s+AND\s+", alternative.strip())
            if part.strip()
        ]
        for alternative in alternatives
        if alternative.strip()
    ]


def categorize(expression: str | None) -> str:
    """Categorize a license expression by the least restrictive usable option.

    A dual license such as ``MIT OR LGPL-2.1-or-later`` is permissive because
    Umbra can take the permissive option; ``MIT AND MPL-2.0`` is not, because
    both apply.
    """

    if not expression:
        return "unknown"
    best = "unknown"
    order = {
        "permissive": 0,
        "public domain": 1,
        "non-OSI permissive": 2,
        "weak copyleft": 3,
        "strong copyleft": 4,
        "unknown": 5,
    }
    for alternative in split_expression(expression):
        if not alternative:
            continue
        worst = "permissive"
        for identifier in alternative:
            if identifier in PERMISSIVE:
                category = "permissive"
            elif identifier in PUBLIC_DOMAIN:
                category = "public domain"
            elif identifier in NON_OSI_PERMISSIVE:
                category = "non-OSI permissive"
            elif identifier in WEAK_COPYLEFT:
                category = "weak copyleft"
            elif identifier in STRONG_COPYLEFT:
                category = "strong copyleft"
            else:
                category = "unknown"
            if order[category] > order[worst]:
                worst = category
        if order[worst] < order[best]:
            best = worst
    return best


def cargo_closure(manifest_dir: Path, package: str, targets: tuple[str, ...]) -> list[dict]:
    """Return the locked non-dev dependency closure of one Cargo package."""

    found: dict[tuple[str, str], dict] = {}
    for target in targets:
        metadata = json.loads(
            subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    target,
                ],
                cwd=manifest_dir,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
        )
        packages = {item["id"]: item for item in metadata["packages"]}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        roots = [
            identifier
            for identifier in metadata["workspace_members"]
            if packages[identifier]["name"] == package
        ]
        if len(roots) != 1:
            raise ReportError(
                f"expected one workspace package named {package!r} in {manifest_dir}"
            )
        pending = [roots[0]]
        seen: set[str] = set()
        while pending:
            identifier = pending.pop()
            if identifier in seen:
                continue
            seen.add(identifier)
            for dependency in nodes[identifier]["deps"]:
                kinds = dependency.get("dep_kinds", [])
                if kinds and all(kind.get("kind") == "dev" for kind in kinds):
                    continue
                pending.append(dependency["pkg"])
        for identifier in seen - {roots[0]}:
            item = packages[identifier]
            found[(item["name"], item["version"])] = {
                "name": item["name"],
                "version": item["version"],
                "license": item.get("license"),
                "note": (
                    f"license file: {item['license_file']}"
                    if not item.get("license") and item.get("license_file")
                    else ""
                ),
            }
    return sorted(found.values(), key=lambda item: (item["name"], item["version"]))


def uv_closure(lock: Path, extras: tuple[str, ...]) -> list[dict]:
    """Return the locked runtime (non-dev) dependency closure of a uv project."""

    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    packages = {item["name"]: item for item in data["package"]}
    roots = [
        item["name"]
        for item in data["package"]
        if "editable" in item.get("source", {}) or "virtual" in item.get("source", {})
    ]
    if len(roots) != 1:
        raise ReportError(f"{lock}: expected exactly one first-party project")
    project = packages[roots[0]]
    edges: list[tuple[dict, str | None]] = [
        (dependency, dependency.get("marker"))
        for dependency in project.get("dependencies", [])
    ]
    for extra in extras:
        edges += [
            (dependency, dependency.get("marker"))
            for dependency in project.get("optional-dependencies", {}).get(extra, [])
        ]

    # A package reached only through marked edges is locked but not installed on
    # every platform; record the markers so a copyleft finding that cannot reach
    # the published Linux image is visible as such.
    markers: dict[str, set[str | None]] = {}
    pending = list(edges)
    while pending:
        dependency, marker = pending.pop()
        name = dependency["name"]
        first_visit = name not in markers
        markers.setdefault(name, set()).add(marker)
        if not first_visit:
            continue
        item = packages.get(name)
        if item is None:
            raise ReportError(f"{lock}: dependency {name!r} is not locked")
        children = list(item.get("dependencies", []))
        for group in item.get("optional-dependencies", {}).values():
            children += group
        for child in children:
            # An unmarked child of a marked parent is still gated by the parent.
            pending.append((child, child.get("marker") or marker))

    entries = []
    for name, reached_by in markers.items():
        version = packages[name]["version"]
        resolved = pypi_license(name, version)
        if None not in reached_by:
            gate = "; ".join(sorted(item for item in reached_by if item))
            resolved["note"] = (
                f"{resolved['note']} — " if resolved["note"] else ""
            ) + f"installed only when: {gate}"
        entries.append({"name": name, "version": version, **resolved})
    return sorted(entries, key=lambda item: item["name"])


def pypi_license(name: str, version: str) -> dict[str, str | None]:
    """Resolve one locked wheel's declared license from immutable PyPI metadata."""

    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            info = json.load(response)["info"]
    except (urllib.error.URLError, TimeoutError) as error:
        raise ReportError(f"could not read PyPI metadata for {name} {version}: {error}")
    expression = (info.get("license_expression") or "").strip()
    note = ""
    if not expression:
        identifiers = [
            CLASSIFIERS[item]
            for item in info.get("classifiers", [])
            if item in CLASSIFIERS
        ]
        declared = (info.get("license") or "").strip()
        if identifiers:
            expression = " AND ".join(sorted(set(identifiers)))
            note = "from trove classifiers"
        elif declared and len(declared) <= 40 and "\n" not in declared:
            expression = normalize(declared)
            note = "from the prose `License` field"
    return {"license": expression or None, "note": note}


def npm_registry_license(name: str, version: str) -> str | None:
    """Resolve a license the npm lock omits from the published registry manifest."""

    url = f"https://registry.npmjs.org/{name.replace('/', '%2f')}/{version}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            manifest = json.load(response)
    except (urllib.error.URLError, TimeoutError) as error:
        raise ReportError(f"could not read npm metadata for {name} {version}: {error}")
    value = manifest.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    return value or None


def npm_entries(lock: Path, *, dev: bool) -> list[dict]:
    """Return locked npm packages, split by whether they are dev-only."""

    data = json.loads(lock.read_text(encoding="utf-8"))
    found: dict[tuple[str, str], dict] = {}
    for path, item in data.get("packages", {}).items():
        if not path:
            continue
        if bool(item.get("dev")) is not dev:
            continue
        name = item.get("name") or path.split("node_modules/", 1)[-1]
        version = item.get("version", "")
        license_value = item.get("license")
        if isinstance(license_value, dict):
            license_value = license_value.get("type")
        note = ""
        if not license_value:
            license_value = npm_registry_license(name, version)
            note = "from the npm registry manifest"
        found[(name, version)] = {
            "name": name,
            "version": version,
            "license": license_value,
            "note": note if license_value else "",
        }
    return sorted(found.values(), key=lambda item: (item["name"], item["version"]))


def table(entries: list[dict]) -> str:
    """Render one inventory table with a category column for review triage."""

    lines = [
        "| Package | Version | Declared license | Category | Note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in entries:
        category = categorize(entry["license"])
        lines.append(
            f"| `{entry['name']}` | {entry['version']} | "
            f"{entry['license'] or '_none declared_'} | {category} | "
            f"{entry['note'] or '—'} |"
        )
    return "\n".join(lines)


def summary(sections: list[tuple[str, str, list[dict]]]) -> str:
    """Render the counts-per-category summary and the review-required table."""

    lines = ["| Inventory | Packages | Permissive | Needs review |", "| --- | --- | --- | --- |"]
    flagged: list[tuple[str, dict, str]] = []
    for title, _, entries in sections:
        permissive = 0
        needs = 0
        for entry in entries:
            category = categorize(entry["license"])
            if category in REVIEW_CATEGORIES:
                needs += 1
                flagged.append((title, entry, category))
            else:
                permissive += 1
        lines.append(f"| {title} | {len(entries)} | {permissive} | {needs} |")
    out = ["\n".join(lines), ""]
    if flagged:
        out += [
            "Every row below is unapproved until a maintainer records a decision"
            " in this file's **Maintainer review queue** section.",
            "",
            "| Inventory | Package | Version | Declared license | Category | Note |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for title, entry, category in sorted(
            flagged, key=lambda item: (item[2], item[1]["name"])
        ):
            out.append(
                f"| {title} | `{entry['name']}` | {entry['version']} | "
                f"{entry['license'] or '_none declared_'} | {category} | "
                f"{entry['note'] or '—'} |"
            )
    else:
        out.append("No dependency license requires maintainer review.")
    return "\n".join(out)


def build() -> str:
    """Assemble every generated inventory section for the notices artifact."""

    sections: list[tuple[str, str, list[dict]]] = [
        (
            "Rust — `umbra` CLI",
            "Locked non-dev closure of `umbra-cli`, unioned across the published"
            f" targets ({', '.join(f'`{item}`' for item in CLI_TARGETS)})."
            " Distributed as release binaries and as the `umbra-cli` crate.",
            cargo_closure(ROOT, "umbra-cli", CLI_TARGETS),
        ),
        (
            "Rust — `umbra-atls-connect`",
            "Locked non-dev closure for `" + IMAGE_TARGET + "`. Distributed inside"
            " the Dev CVM image.",
            cargo_closure(ROOT, "umbra-atls-connect", (IMAGE_TARGET,)),
        ),
        (
            "Rust — `atlas-verify-cli`",
            "Locked non-dev closure for `" + IMAGE_TARGET + "` from"
            " `console/atlas-verify/Cargo.lock`. Builds the `umbra-atlas-verify`"
            " binary distributed inside the Console image.",
            cargo_closure(
                ROOT / "console" / "atlas-verify", "atlas-verify-cli", (IMAGE_TARGET,)
            ),
        ),
        (
            "Python — Console",
            "Locked runtime closure of `umbra-console` from `console/uv.lock`"
            " (`uv sync --frozen --no-dev`, as the Console image installs it).",
            uv_closure(ROOT / "console" / "uv.lock", ()),
        ),
        (
            "Python — Security CVM",
            "Locked runtime closure of `umbra-security-cvm` from"
            " `cvms/security/uv.lock` including the `mitmproxy` extra"
            " (`uv sync --frozen --no-dev --extra mitmproxy`, as the Security CVM"
            " image installs it).",
            uv_closure(ROOT / "cvms" / "security" / "uv.lock", ("mitmproxy",)),
        ),
        (
            "npm — Console runtime (`phala` CLI)",
            "Non-dev entries of `console/package-lock.json`. The Console image"
            " retains this graph after `npm prune --omit=dev`; the Console shells"
            " out to the pinned Phala CLI through its provider adapter.",
            npm_entries(ROOT / "console" / "package-lock.json", dev=False),
        ),
        (
            "npm — dashboard build graph (build-time only)",
            "**Build-time only — not distributed.** Dev-only entries of"
            " `console/package-lock.json`: the Tailwind graph that compiles"
            " `console/static/admin/tailwind.in.css` into `tailwind.css` in the"
            " isolated `webapp-builder` stage. `npm prune --omit=dev` removes"
            " every package below before the runtime stage copies `node_modules`,"
            " so none of it ships in the Console image. Listed for build-input"
            " transparency (OSS-07).",
            npm_entries(ROOT / "console" / "package-lock.json", dev=True),
        ),
        (
            "npm — Codex (Dev CVM image)",
            "`cvms/dev/user-sandbox/codex-package/package-lock.json`, installed"
            " into the Dev CVM image with `npm ci --omit=dev`. Only the"
            " `linux-x64` optional platform package is installed at build time;"
            " every platform package is listed because the lock pins them all.",
            npm_entries(
                ROOT / "cvms" / "dev" / "user-sandbox" / "codex-package" / "package-lock.json",
                dev=False,
            ),
        ),
    ]

    blocks = [
        BEGIN_MARKER,
        "",
        "<!-- Regenerate with tools/generate-license-report.py; do not hand-edit"
        " between the generated markers. -->",
        "",
        "## Inventory summary and review queue",
        "",
        summary(sections),
        "",
    ]
    for title, description, entries in sections:
        blocks += [f"## {title}", "", description, "", table(entries), ""]
    blocks.append(END_MARKER)
    return "\n".join(blocks)


def main() -> int:
    """Rewrite (or verify) the generated inventory in THIRD_PARTY_NOTICES.md."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the artifact does not match the locks",
    )
    args = parser.parse_args()

    current = ARTIFACT.read_text(encoding="utf-8")
    start = current.find(BEGIN_MARKER)
    end = current.find(END_MARKER)
    if start < 0 or end < 0:
        raise ReportError(f"{ARTIFACT}: generated inventory markers are missing")
    updated = current[:start] + build() + current[end + len(END_MARKER) :]
    if args.check:
        if updated != current:
            print(
                f"{ARTIFACT} is stale; regenerate it with"
                " tools/generate-license-report.py",
                file=sys.stderr,
            )
            return 1
        print(f"{ARTIFACT} matches the locked dependency graphs")
        return 0
    ARTIFACT.write_text(updated, encoding="utf-8")
    print(f"wrote {ARTIFACT}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
