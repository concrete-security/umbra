#!/usr/bin/env python3
"""Require a matching Developer Certificate of Origin sign-off per commit."""

from __future__ import annotations

import re
import subprocess
import sys


SIGN_OFF_RE = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^<>]+)>\s*$", re.IGNORECASE | re.MULTILINE)


def main() -> int:
    """Check commits in the base-exclusive, head-inclusive revision range."""
    if len(sys.argv) != 3:
        print("usage: check-dco.py <base-sha> <head-sha>", file=sys.stderr)
        return 2

    base, head = sys.argv[1:]
    commits = subprocess.run(
        ["git", "rev-list", "--reverse", f"{base}..{head}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if not commits:
        print("DCO check found no pull request commits", file=sys.stderr)
        return 1

    failures: list[str] = []
    for commit in commits:
        fields = subprocess.run(
            ["git", "show", "-s", "--format=%H%x00%an%x00%ae%x00%B", commit],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split("\0", 3)
        if len(fields) != 4:
            failures.append(f"{commit}: could not read commit metadata")
            continue

        full_sha, author_name, author_email, message = fields
        signoffs = {(name.strip().casefold(), email.strip().casefold()) for name, email in SIGN_OFF_RE.findall(message)}
        expected = (author_name.strip().casefold(), author_email.strip().casefold())
        if expected not in signoffs:
            failures.append(
                f"{full_sha[:12]}: missing Signed-off-by: {author_name.strip()} <{author_email.strip()}>"
            )

    if failures:
        print("DCO sign-off check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("Amend each commit with `git commit --amend --signoff` and rebase as needed.", file=sys.stderr)
        return 1

    print(f"DCO sign-off check passed for {len(commits)} commit(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
