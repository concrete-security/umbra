#!/usr/bin/env python3
"""Render an inert native candidate, or the same core for the isolated CI harness."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
BINARIES = ("sysbox-runc", "sysbox-mgr", "sysbox-fs")
UNITS = (
    "dstack-prepare.service", "app-compose.service", "docker.service", "docker.socket",
    "containerd.service", "sysbox.service", "sysbox-mgr.service", "sysbox-fs.service",
    "dstack-guest-agent.service",
)
RUNTIME_UNITS = (
    "app-compose.service", "docker.service", "containerd.service", "sysbox.service",
    "sysbox-mgr.service", "sysbox-fs.service",
)
PINS = {
    "sysbox-runc": "52fb39f5495d7bee0ecff998e91f51c0239a87b99a22d150d7ede8b07e1c0b9e",
    "sysbox-mgr": "1e7894fc500669edf159ad3512ad58eeed5e15db54995af5b426033c1fc071aa",
    "sysbox-fs": "e34ecbddfa1555e6e1543698e990fe111a20eb2583c451d33aab2bcd03bdb8ba",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_url(value: str) -> str:
    """Accept public HTTPS artifact URLs, never credentials or shell syntax."""
    # urlsplit removes some control characters; reject them in the original bytes.
    if not re.fullmatch(r"https://[a-z0-9.-]+/[A-Za-z0-9_./+-]+", value):
        raise ValueError("artifact URL contains unsupported characters")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment
        or parsed.netloc != parsed.hostname or len(value) > 2048
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", parsed.hostname)
        or "." not in parsed.hostname or ".." in parsed.hostname
        or not re.fullmatch(r"/[A-Za-z0-9_./+-]+", parsed.path)
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ValueError("artifact URL must be credential-free HTTPS with a plain absolute path")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("artifact URL must use a public DNS name")
    if parsed.hostname.endswith((".localhost", ".local", ".internal", ".invalid")):
        raise ValueError("artifact URL must use a public DNS name")
    labels = parsed.hostname.split(".")
    if (
        len(parsed.hostname) > 253
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        # curl accepts abbreviated, octal and hexadecimal IPv4 forms that
        # ipaddress rejects. An alphabetic DNS suffix excludes those aliases.
        or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
    ):
        raise ValueError("artifact URL must use ordinary DNS labels and an alphabetic suffix")
    return value


def fixtures(version: str) -> dict[str, bytes]:
    manifest = json.loads((HERE / "fixtures/manifest.json").read_text())
    if version not in manifest["versions"]:
        raise ValueError("unsupported fixture version")
    listed = [row["file"] for row in manifest["sources"]]
    if len(set(listed)) != len(listed):
        raise ValueError("duplicate fixture manifest path")
    actual = set()
    for path in (HERE / "fixtures").rglob("*"):
        if path.is_symlink():
            raise ValueError("fixture inventory contains a symlink")
        if path.is_file() and path != HERE / "fixtures/manifest.json":
            actual.add(str(path.relative_to(HERE)))
    if actual != set(listed):
        raise ValueError("fixture inventory does not match the complete manifest")
    checked = {}
    for row in manifest["sources"]:
        content = (HERE / row["file"]).read_bytes()
        if digest(content) != row["sha256"]:
            raise ValueError(f"fixture checksum mismatch: {row['file']}")
        git_blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if git_blob != row["git_blob"]:
            raise ValueError(f"fixture Git blob mismatch: {row['file']}")
        checked[row["file"]] = content
    result = {
        path.removeprefix("fixtures/common/"): content
        for path, content in checked.items() if path.startswith("fixtures/common/")
    }
    result["app-compose.service"] = checked[f"fixtures/{version}/app-compose.service"]
    transform = manifest["install_transform"]["containerd.service"]
    result["containerd.service"] = result["containerd.service"].replace(
        transform["from"].encode(), transform["to"].encode()
    )
    return result


@dataclass(frozen=True)
class Layout:
    prefix: str = ""
    root: str = ""

    def unit(self, name: str) -> str:
        return self.prefix + name

    @property
    def unit_dir(self) -> str:
        return "/run/systemd/system"

    @property
    def bin_dir(self) -> str:
        return self.root + "/usr/bin"

    @property
    def runtime_dir(self) -> str:
        return self.root + "/run/umbra-sysbox-bootstrap"

    @property
    def socket_dir(self) -> str:
        return self.root + "/run/sysbox"

    @property
    def cache_dir(self) -> str:
        return self.root + "/var/volatile/dstack/persistent/umbra-runtime-cache/sysbox-0.7.1-umbra.1"

    def validate(self) -> None:
        if not self.prefix and not self.root:
            return
        if not re.fullmatch(r"umbra-sbq-[a-f0-9]{12}-", self.prefix):
            raise ValueError("test unit prefix is not isolated")
        if self.root != "/run/" + self.prefix[:-1]:
            raise ValueError("test root does not match its isolated unit prefix")


def _substitute(name: str, values: dict[str, str]) -> str:
    text = (HERE / name).read_text()
    for key, value in values.items():
        text = text.replace("@@" + key + "@@", value)
    if re.search(r"@@[A-Z_]+@@", text):
        raise ValueError("unresolved template token")
    return text


def render(
    version: str, urls: dict[str, str], *, layout: Layout = Layout(),
    source_files: dict[str, bytes] | None = None, pins: dict[str, str] | None = None,
) -> str:
    """The native output always holds. Only the prefixed harness can run the core."""
    layout.validate()
    if set(urls) != set(BINARIES):
        raise ValueError("exactly three artifact URLs are required")
    urls = {name: validate_url(urls[name]) for name in BINARIES}
    if not layout.prefix and (pins is not None or source_files is not None):
        raise ValueError("native pins and source fixtures cannot be overridden")
    pins = PINS if pins is None else pins
    if set(pins) != set(BINARIES) or any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values()):
        raise ValueError("invalid binary pins")
    source_files = fixtures(version) if source_files is None else source_files
    fragments = []
    drops = []
    for unit in UNITS:
        name = layout.unit(unit)
        fragments.append(f"{name} {digest(source_files[name])}")
        paths = [path for path in source_files if path.startswith(name + ".d/")]
        drops.append(f"{name} {len(paths)}")
        for path in sorted(paths):
            drops.append(f"{path} {digest(source_files[path])}")
    q = shlex.quote
    values = {
        "PREFIX": q(layout.prefix), "ROOT": q(layout.root), "BIN_DIR": q(layout.bin_dir),
        "CACHE_DIR": q(layout.cache_dir), "RUNTIME_DIR": q(layout.runtime_dir),
        "SOCKET_DIR": q(layout.socket_dir), "UNIT_DIR": q(layout.unit_dir),
        "PREPARE": q(layout.unit("dstack-prepare.service")),
        "READY": q(layout.unit("umbra-sysbox-ready.service")),
        "DOCKER_SOCKET": q(layout.unit("docker.socket")),
        "RUNTIME_UNITS": " ".join(q(layout.unit(name)) for name in RUNTIME_UNITS),
        "FRAGMENTS": "\n".join(fragments), "DROPS": "\n".join(drops),
        "ARTIFACTS": "\n".join(f"{name} {pins[name]} {urls[name]}" for name in BINARIES),
        "MGR_UNIT": q(layout.unit("sysbox-mgr.service")),
        "FS_UNIT": q(layout.unit("sysbox-fs.service")),
        "MGR_HASH": q(pins["sysbox-mgr"]), "FS_HASH": q(pins["sysbox-fs"]),
        "RUNC_HASH": q(pins["sysbox-runc"]),
        "QUALIFICATION_HOLD": (
            'hold "native use blocked: CI, full-compose and provider recovery evidence incomplete"'
            if not layout.prefix else ": # Strictly prefixed runner fixture; no native enable switch."
        ),
    }
    ready_script = _substitute("ready.sh.in", values)
    unit = (
        "[Unit]\nDescription=Measured Sysbox startup qualification gate\n"
        f"Requires={layout.unit('dstack-prepare.service')} {layout.unit('sysbox-mgr.service')} "
        f"{layout.unit('sysbox-fs.service')}\n"
        f"After={layout.unit('dstack-prepare.service')} {layout.unit('sysbox-mgr.service')} "
        f"{layout.unit('sysbox-fs.service')}\n\n"
        "[Service]\nType=oneshot\nTimeoutStartSec=35\n"
        f"ExecStart=/bin/bash {layout.runtime_dir}/ready.sh\n"
    )
    writes = [
        f"write_file {q(layout.runtime_dir + '/ready.sh')} 0700 <<'UMBRA_READY_SCRIPT'\n"
        + ready_script + "UMBRA_READY_SCRIPT\n",
        f"write_file {q(layout.unit_dir + '/' + layout.unit('umbra-sysbox-ready.service'))} 0644 "
        "<<'UMBRA_READY_UNIT'\n" + unit + "UMBRA_READY_UNIT\n",
    ]
    for name in ("docker.service", "containerd.service", "app-compose.service"):
        path = layout.unit_dir + "/" + layout.unit(name) + ".d/90-umbra-sysbox-ready.conf"
        body = (
            "[Unit]\n"
            f"Requires={layout.unit('umbra-sysbox-ready.service')} {layout.unit('dstack-prepare.service')}\n"
            f"After={layout.unit('umbra-sysbox-ready.service')} {layout.unit('dstack-prepare.service')}\n"
        )
        writes.append(f"write_file {q(path)} 0644 <<'UMBRA_GATE'\n{body}UMBRA_GATE\n")
    values["WRITES"] = "\n".join(writes)
    return _substitute("hook.sh.in", values)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-version", required=True, choices=("0.5.9", "0.5.12"))
    for name in BINARIES:
        parser.add_argument("--" + name + "-url", required=True)
    args = parser.parse_args()
    urls = {name: getattr(args, name.replace("-", "_") + "_url") for name in BINARIES}
    print(render(args.os_version, urls), end="")


if __name__ == "__main__":
    main()
