#!/usr/bin/env python3
"""Keep the scoped Hickory DNSSEC advisory exception bound to disabled features."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (ROOT / "Cargo.toml", ROOT / "console/atlas-verify/Cargo.toml")

for manifest in MANIFESTS:
    result = subprocess.run(
        [
            "cargo", "metadata", "--locked", "--format-version", "1",
            "--filter-platform", "x86_64-unknown-linux-gnu",
            "--manifest-path", str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    packages = {p["id"]: p for p in metadata["packages"]}
    for node in metadata["resolve"]["nodes"]:
        package = packages[node["id"]]
        if package["name"] != "hickory-resolver":
            continue
        if package["version"] != "0.25.2":
            raise SystemExit("Reassess the Hickory advisory exception after a version change")
        if any("dnssec" in feature for feature in node["features"]):
            raise SystemExit("The Hickory advisory exception requires DNSSEC features disabled")
