#!/usr/bin/env python3
"""Select one public Umbra CLI release and its exact required assets."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


TAG_PREFIX = "umbra-cli/"
REQUIRED_ASSETS = (
    "umbra-cli-release-tree.tar.gz",
    "umbra-cli.intoto.jsonl",
    "umbra-install.sh",
    "SHA256SUMS",
)
REPOSITORY = re.compile(r"[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def fail(message: str) -> None:
    raise SystemExit(f"select-public-cli-release: {message}")


def semver_key(version: str) -> tuple[tuple[int, int, int], int, tuple[tuple[int, int | str], ...]] | None:
    match = SEMVER.fullmatch(version)
    if match is None:
        return None
    prerelease = match.group(4)
    identifiers: list[tuple[int, int | str]] = []
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    return None
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
    return (
        (int(match.group(1)), int(match.group(2)), int(match.group(3))),
        1 if prerelease is None else 0,
        tuple(identifiers),
    )


def is_loopback(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def valid_asset_url(url: object, name: str, *, allow_loopback_http: bool) -> str | None:
    if not isinstance(url, str) or any(character.isspace() for character in url):
        return None
    parsed = urlsplit(url)
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        return None
    production_url = (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.hostname.lower() == "github.com"
    )
    test_url = (
        allow_loopback_http
        and parsed.scheme == "http"
        and is_loopback(parsed.hostname)
    )
    if not (production_url or test_url):
        return None
    if unquote(parsed.path).rsplit("/", 1)[-1] != name:
        return None
    return url


def candidate(
    release: object,
    *,
    repo: str,
    allow_loopback_http: bool,
) -> tuple[
    tuple[tuple[int, int, int], int, tuple[tuple[int, int | str], ...]],
    str,
    str,
    dict[str, str],
] | None:
    if not isinstance(release, dict) or release.get("draft") is not False:
        return None
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith(TAG_PREFIX):
        return None
    version = tag.removeprefix(TAG_PREFIX)
    key = semver_key(version)
    if key is None:
        return None

    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        return None
    assets: dict[str, str] = {}
    seen_names: set[str] = set()
    for raw_asset in raw_assets:
        if not isinstance(raw_asset, dict) or not isinstance(raw_asset.get("name"), str):
            return None
        name = raw_asset["name"]
        if name in seen_names:
            return None
        seen_names.add(name)
        if name not in REQUIRED_ASSETS:
            continue
        url = valid_asset_url(
            raw_asset.get("browser_download_url"),
            name,
            allow_loopback_http=allow_loopback_http,
        )
        if url is None:
            return None
        expected_prefix = f"https://github.com/{repo}/releases/download/"
        if not allow_loopback_http and not url.startswith(expected_prefix):
            return None
        assets[name] = url
    if set(assets) != set(REQUIRED_ASSETS):
        return None
    return key, version, tag, assets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("repo")
    parser.add_argument("--tag")
    parser.add_argument("--allow-loopback-http", action="store_true")
    args = parser.parse_args()

    if REPOSITORY.fullmatch(args.repo) is None:
        fail(f"invalid GitHub repository: {args.repo}")
    requested_tag = args.tag
    if requested_tag is not None:
        if not requested_tag.startswith(TAG_PREFIX):
            fail(f"release tag must start with {TAG_PREFIX}")
        if semver_key(requested_tag.removeprefix(TAG_PREFIX)) is None:
            fail(f"requested release tag is not canonical SemVer: {requested_tag}")

    try:
        releases = json.loads(args.metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read GitHub release metadata: {error}")
    if not isinstance(releases, list):
        fail("GitHub release metadata is not a list")

    candidates = [
        selected
        for release in releases
        if (selected := candidate(
            release,
            repo=args.repo,
            allow_loopback_http=args.allow_loopback_http,
        ))
        is not None
        and (requested_tag is None or selected[2] == requested_tag)
    ]
    if not candidates:
        if requested_tag is None:
            fail("no non-draft canonical CLI release has the required assets")
        fail(f"requested public release is unavailable or incomplete: {requested_tag}")
    if requested_tag is not None and len(candidates) != 1:
        fail(f"GitHub returned duplicate releases for tag: {requested_tag}")

    _, version, tag, assets = max(candidates, key=lambda item: (item[0], item[1]))
    print(version)
    print(tag)
    for name in REQUIRED_ASSETS:
        print(assets[name])


if __name__ == "__main__":
    main()
