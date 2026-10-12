#!/usr/bin/env python3
"""Exercise an installed pre-Umbra updater against a local migration channel."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path


def run(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=environment, capture_output=True, text=True, timeout=60)


def check(concrete: Path, bridge: Path, bridge_version: str, corrupt_checksum: bool = False, shim: bool = False, conflict: bool = False, saved_origin: bool = True) -> None:
    with tempfile.TemporaryDirectory(prefix="umbra-update-bridge-") as name:
        root = Path(name)
        binaries = root / "bin"
        binaries.mkdir()
        old = binaries / "concrete"
        shutil.copy2(concrete, old)
        if shim:
            storage = root / "storage"
            storage.mkdir()
            old.rename(storage / "concrete")
            old.symlink_to("../storage/concrete")
        if conflict:
            (binaries / "umbra").write_text("preserve existing installation")
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("UMBRA_", "CONCRETE_"))
        }
        environment.update(HOME=str(root), PATH=str(binaries) + os.pathsep + environment["PATH"])
        environment["CONCRETE_NO_UPDATE_CHECK"] = "1"
        environment["UMBRA_NO_UPDATE_CHECK"] = "1"
        metadata = run([str(old), "--json", "version"], environment)
        assert metadata.returncode == 0, metadata.stderr
        target = json.loads(metadata.stdout)["target"]
        releases = root / "releases" / "concrete-cli"
        release = releases / bridge_version / target
        release.mkdir(parents=True)
        (release / "concrete").write_bytes(bridge.read_bytes())
        digest = hashlib.sha256(bridge.read_bytes()).hexdigest()
        (release / "concrete.sha256").write_text(
            ("0" * 64 if corrupt_checksum else digest) + "  concrete\n"
        )
        (releases / "latest").mkdir()
        (releases / "latest" / "version").write_text(bridge_version + "\n")

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=root, **kwargs)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            environment["CONCRETE_INSTALL_BASE_URL"] = origin
            legacy = root / ".concrete"
            (legacy / "cvms").mkdir(parents=True)
            state = {
                "config.toml": (
                    "console_url = 'https://console.example.com'\n"
                    "default_cvm = 'migration-box'\n" +
                    (f"install_base_url = '{origin}'\n" if saved_origin else "") +
                    "no_update_check = true\n"
                ),
                "session.json": "fake credential fixture",
                "aliases.toml": "fake alias fixture",
                "ssh-identities.toml": "fake identity fixture",
                "cvms/migration-box.atls-policy.json": "fake pinned policy fixture",
                "cvms/migration-box.state.toml": "workspace = '/home/dev/workspaces/repo'\n",
            }
            for filename, contents in state.items():
                (legacy / filename).write_text(contents)
            original = hashlib.sha256(old.read_bytes()).hexdigest()
            update = run([str(old), "--json", "update"], environment)
            if conflict:
                assert update.returncode != 0, "existing Umbra command was replaced"
                assert hashlib.sha256(old.read_bytes()).hexdigest() == original
                assert (binaries / "umbra").read_text() == "preserve existing installation"
                assert not (root / ".umbra").exists()
                print("Existing Umbra installation is preserved.")
                return
            if corrupt_checksum:
                assert update.returncode != 0, "corrupt checksum installed"
                assert hashlib.sha256(old.read_bytes()).hexdigest() == original
                assert not (binaries / "umbra").exists()
                assert not (root / ".umbra").exists()
                print("Corrupt legacy download leaves installation and state unchanged.")
                return
            assert update.returncode == 0, update.stderr
            assert json.loads(update.stdout)["version"] == bridge_version
            assert hashlib.sha256(old.read_bytes()).hexdigest() == digest
            assert (binaries / "umbra").is_symlink(), "Umbra command unavailable after update"
            config = run(["umbra", "--json", "config", "show"], environment)
            assert config.returncode == 0, config.stderr
            assert json.loads(config.stdout)["default_cvm"]["value"] == "migration-box"
            for filename, contents in state.items():
                assert (legacy / filename).read_text() == contents
                if filename != "config.toml" or saved_origin:
                    assert (root / ".umbra" / filename).read_text() == contents
            if not saved_origin:
                import tomllib
                imported = tomllib.loads((root / ".umbra/config.toml").read_text())
                assert imported["install_base_url"].startswith("https://")
            assert (binaries / ".umbra-slsa-verifier-v2.7.1").is_file()
            verifier = run([str(binaries / ".umbra-slsa-verifier-v2.7.1"), "version"], environment)
            assert verifier.returncode == 0, verifier.stderr
            future = root / "releases/umbra-cli/0.1.1" / target
            future.mkdir(parents=True)
            (future / "umbra").write_bytes(bridge.read_bytes())
            (future / "umbra.sha256").write_text(digest + "  umbra\n")
            (future.parent / "umbra-cli.intoto.jsonl").write_text("not signed provenance\n")
            upgrade = run(["umbra", "--json", "update", "--version", "0.1.1"], environment)
            assert upgrade.returncode != 0 and "provenance" in upgrade.stderr.lower(), upgrade.stderr
            assert "is required for self-update" not in upgrade.stderr, upgrade.stderr
            assert hashlib.sha256(old.read_bytes()).hexdigest() == digest
            print("Concrete update installs Umbra, imports state, and retains the verified updater tool.")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--concrete", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-version", default="1.0.0")
    args = parser.parse_args()
    check(args.concrete.resolve(), args.bridge.resolve(), args.bridge_version)
    check(args.concrete.resolve(), args.bridge.resolve(), args.bridge_version, shim=True)
    check(args.concrete.resolve(), args.bridge.resolve(), args.bridge_version, saved_origin=False)
    check(args.concrete.resolve(), args.bridge.resolve(), args.bridge_version, corrupt_checksum=True)
    check(args.concrete.resolve(), args.bridge.resolve(), args.bridge_version, conflict=True)


if __name__ == "__main__":
    main()
