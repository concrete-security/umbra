#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from Cargo's locked resolve graph."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote


def package_source(package: dict[str, object], root: Path) -> str:
    """Return a checkout-independent identity for one Cargo package source."""
    source = package.get("source")
    if isinstance(source, str):
        return source
    manifest = Path(str(package["manifest_path"])).resolve()
    try:
        relative = manifest.relative_to(root)
    except ValueError:
        relative = manifest
    return f"path:{relative.parent.as_posix()}"


def component_ref(package: dict[str, object], root: Path) -> str:
    """Build a stable, collision-resistant CycloneDX bom-ref."""
    identity = "\0".join(
        (str(package["name"]), str(package["version"]), package_source(package, root))
    )
    return f"urn:cargo:{hashlib.sha256(identity.encode()).hexdigest()}"


def main() -> int:
    """Write the selected package's target-specific runtime/build dependency SBOM."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, help="Cargo package name")
    parser.add_argument("--target", required=True, help="Rust target triple")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = Path.cwd().resolve()
    metadata = json.loads(
        subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                args.target,
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
    )
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    workspace_ids = set(metadata["workspace_members"])
    roots = [
        package_id
        for package_id in workspace_ids
        if packages[package_id]["name"] == args.package
    ]
    if len(roots) != 1:
        raise SystemExit(f"expected one workspace package named {args.package!r}, found {len(roots)}")
    root_id = roots[0]

    dependency_ids: dict[str, list[str]] = {}
    reachable: set[str] = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        direct: set[str] = set()
        for dependency in nodes[package_id]["deps"]:
            kinds = dependency.get("dep_kinds", [])
            if kinds and all(kind.get("kind") == "dev" for kind in kinds):
                continue
            direct.add(dependency["pkg"])
        dependency_ids[package_id] = sorted(direct)
        pending.extend(direct)

    lock_checksums: dict[tuple[str, str, str | None], str] = {}
    lock_text = (root / "Cargo.lock").read_text(encoding="utf-8")
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", lock_text)[1:]:
        fields = {
            match.group("key"): json.loads(match.group("value"))
            for match in re.finditer(
                r'(?m)^(?P<key>name|version|source|checksum) = (?P<value>"(?:\\.|[^"\\])*")$',
                block,
            )
        }
        if "checksum" in fields:
            lock_checksums[(fields["name"], fields["version"], fields.get("source"))] = fields[
                "checksum"
            ]
    refs = {package_id: component_ref(packages[package_id], root) for package_id in reachable}

    def component(package_id: str, *, component_type: str) -> dict[str, object]:
        package = packages[package_id]
        source = package_source(package, root)
        item: dict[str, object] = {
            "type": component_type,
            "bom-ref": refs[package_id],
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}",
            "properties": [{"name": "cargo:source", "value": source}],
        }
        license_expression = package.get("license")
        if license_expression:
            item["licenses"] = [{"expression": license_expression}]
        checksum = lock_checksums.get(
            (package["name"], package["version"], package.get("source"))
        )
        if checksum:
            item["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        references = []
        for field, reference_type in (
            ("repository", "vcs"),
            ("homepage", "website"),
            ("documentation", "documentation"),
        ):
            if package.get(field):
                references.append({"type": reference_type, "url": package[field]})
        if references:
            item["externalReferences"] = references
        return item

    bom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": component(root_id, component_type="application"),
            "properties": [{"name": "cargo:target", "value": args.target}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "generate-cargo-sbom.py",
                        "version": "1",
                    }
                ]
            },
        },
        "components": [
            component(package_id, component_type="library")
            for package_id in sorted(reachable - {root_id}, key=lambda item: refs[item])
        ],
        "dependencies": [
            {
                "ref": refs[package_id],
                "dependsOn": sorted(
                    refs[dependency_id]
                    for dependency_id in dependency_ids[package_id]
                    if dependency_id in reachable
                ),
            }
            for package_id in sorted(reachable, key=lambda item: refs[item])
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
