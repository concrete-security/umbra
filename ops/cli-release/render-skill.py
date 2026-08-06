#!/usr/bin/env python3
"""Generate the shipped umbra-cli skill from the repo crib.

Source of truth: skills/umbra-cli/SKILL.md — edited directly; agents read it.
`<!-- only:internal -->` / `<!-- only:enduser -->` markers (block or inline,
documented in CLAUDE.md / AGENTS.md) split repo-internal notes from the copy
shipped to end users. This renders the end-user copy and its in-crate mirror:

    dist/skills/umbra-cli/SKILL.md
    cli/assets/umbra-cli/SKILL.md

Run via `make skill`; `--check` writes nothing and exits 1 if it is stale.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "skills/umbra-cli/SKILL.md"
DIST = ROOT / "dist/skills/umbra-cli/SKILL.md"
CLI_ASSET = ROOT / "cli/assets/umbra-cli/SKILL.md"
OUTPUTS = (DIST, CLI_ASSET)


def render_enduser(src):
    # Drop internal spans, then strip the (now end-user-only) markers. Block
    # markers each sit on their own line; inline markers open and close on one.
    src = re.sub(r"(?ms)^[ \t]*<!-- only:internal -->\n.*?^[ \t]*<!-- only:end -->\n", "", src)
    src = re.sub(r"<!--only:internal-->.*?<!--/only-->", "", src)
    src = re.sub(r"(?m)^[ \t]*<!-- only:(?:enduser|end) -->\n", "", src)
    src = re.sub(r"<!--only:enduser-->(.*?)<!--/only-->", r"\1", src)

    if re.search(r"<!--\s*/?only", src):
        raise SystemExit(
            f"{SOURCE}: leftover marker after render — an inline `<!--only:...-->` "
            "span must open and close on one line; use a block "
            "(`<!-- only:internal -->` … `<!-- only:end -->`) for multi-line content"
        )
    return src if src.endswith("\n") else src + "\n"


def main(argv):
    rendered = render_enduser(SOURCE.read_text())
    stale = [output for output in OUTPUTS if not output.exists() or output.read_text() != rendered]
    if not stale:
        return 0
    if "--check" in argv:
        paths = ", ".join(str(output.relative_to(ROOT)) for output in stale)
        print(f"stale: {paths} — run `make skill`", file=sys.stderr)
        return 1
    for output in stale:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        print(f"wrote {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
