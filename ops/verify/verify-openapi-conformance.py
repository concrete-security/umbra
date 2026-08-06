#!/usr/bin/env python3
"""OpenAPI conformance check (docs/specs/console.md §19.6)."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "console" / "openapi.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    base = os.environ.get("CONSOLE_URL", "http://127.0.0.1:8000").rstrip("/")
    if not GOLDEN.is_file():
        print(f"missing golden OpenAPI file: {GOLDEN}", file=sys.stderr)
        return 2
    golden = load_json(GOLDEN)
    url = f"{base}/openapi.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            live = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"failed to fetch {url}: {exc}", file=sys.stderr)
        return 1
    if live != golden:
        print("OpenAPI mismatch: running server differs from console/openapi.json", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
