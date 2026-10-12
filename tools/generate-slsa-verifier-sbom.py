#!/usr/bin/env python3
"""Record the pinned verifier's compiled Go modules as a CycloneDX SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import quote


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    metadata = subprocess.check_output(["go", "version", "-m", str(args.binary)], text=True)
    modules = []
    main_module = None
    for line in metadata.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[0] in {"mod", "dep"}:
            _, name, version, *checksum = fields
            if fields[0] == "mod":
                main_module = (name, version)
            purl = f"pkg:golang/{quote(name, safe='/')}@{quote(version, safe='')}"
            item = {"type": "library", "name": name, "version": version, "purl": purl, "bom-ref": purl}
            if checksum:
                item["properties"] = [{"name": "go:module-checksum", "value": checksum[0]}]
            modules.append(item)
    if main_module != ("github.com/slsa-framework/slsa-verifier/v2", "v2.7.1"):
        raise SystemExit("verifier was not built from the required pinned module")
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {
            "type": "application", "name": "slsa-verifier", "version": "2.7.1",
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(args.binary.read_bytes()).hexdigest()}],
        }},
        "components": sorted(modules, key=lambda item: item["name"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
