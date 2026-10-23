#!/usr/bin/env python3
"""Keep Hickory advisory exceptions bound to their reviewed package and feature graphs."""

import json
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
REVIEWED = {"hickory-resolver": "0.25.2", "hickory-proto": "0.25.2"}
TARGETS = (
    (ROOT / "Cargo.toml", ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin")),
    (ROOT / "console/atlas-verify/Cargo.toml", ("x86_64-unknown-linux-gnu",)),
)


def check_packages(packages):
    """Bind the source review to immutable registry packages, including unselected targets."""
    seen = set()
    for package in packages:
        name = package["name"]
        if name == "hickory-recursor":
            raise ValueError("The CNAME advisory exception requires hickory-recursor absent")
        if name in REVIEWED:
            seen.add(name)
            if package["version"] != REVIEWED[name] or package.get("source") != REGISTRY:
                raise ValueError("Reassess Hickory advisory exceptions after version or source drift")
    if seen != set(REVIEWED):
        raise ValueError("Reassess Hickory advisory exceptions after resolver removal")


def check_metadata(metadata):
    """DNSSEC and CNAME exceptions have independent, fail-closed conditions."""
    packages = {package["id"]: package for package in metadata["packages"]}
    check_packages(packages.values())
    nodes = metadata["resolve"]["nodes"]
    for node in nodes:
        package = packages[node["id"]]
        if package["name"] in REVIEWED and any("dnssec" in feature for feature in node["features"]):
            raise ValueError("The DNSSEC advisory exception requires DNSSEC features disabled")
        if package["name"] != "hickory-resolver":
            continue
        # Reqwest 0.12.28 calls the stub TokioResolver::lookup_ip. The advisory
        # fan-out lives in the separate hickory-recursor crate in this version.
        parents = [parent for parent in nodes if any(dep["pkg"] == node["id"] for dep in parent["deps"])]
        if not parents:
            raise ValueError("The CNAME advisory exception requires the reviewed reqwest stub path")
        for parent in parents:
            client = packages[parent["id"]]
            if (client["name"], client["version"], client.get("source")) != ("reqwest", "0.12.28", REGISTRY):
                raise ValueError("Reassess the CNAME advisory exception after a resolver caller change")
            if "hickory-dns" not in parent["features"]:
                raise ValueError("The CNAME advisory exception requires the reviewed reqwest stub path")


def main():
    for manifest, targets in TARGETS:
        lock = tomllib.loads(manifest.with_name("Cargo.lock").read_text())
        check_packages(lock["package"])
        for target in targets:
            result = subprocess.run(
                ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target,
                 "--manifest-path", str(manifest)],
                check=True, capture_output=True, text=True,
            )
            check_metadata(json.loads(result.stdout))
    print("Hickory advisory exception package, caller and feature guarantees hold")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from error
