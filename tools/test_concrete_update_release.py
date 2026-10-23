"""Release-tree and mirror guarantees for the Concrete migration bridge."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tarfile
from pathlib import Path

import pytest


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
extractor = load("bridge_release_extractor", ROOT / "ops/cli-release/extract-cli-release-tree.py")
publisher = load("bridge_release_publisher", ROOT / "ops/cli-release/prepare-concrete-update-channel.py")


def fixture(root: Path, bridge: bool = True, bridge_version: str = "1.0.0") -> Path:
    tree = root / "tree"
    for channel in ("0.1.0", "latest"):
        directory = tree / channel
        directory.mkdir(parents=True)
        (directory / "version").write_text("0.1.0\n")
        if bridge:
            (directory / "concrete-update-version").write_text(bridge_version + "\n")
        for target in sorted(extractor.TARGETS):
            folder = directory / target
            folder.mkdir()
            for filename in (["umbra", "concrete-update-bridge"] if bridge else ["umbra"]):
                data = (filename + target).encode()
                (folder / filename).write_bytes(data)
                (folder / (filename + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "  " + filename + "\n")
    return tree


def archive(tree: Path, output: Path) -> None:
    with tarfile.open(output, "w:gz") as tar:
        tar.add(tree, arcname=".")


@pytest.mark.parametrize("bridge", [pytest.param(False, id="ordinary-release"), pytest.param(True, id="transition-release")])
def test_release_tree_and_legacy_channel_success(tmp_path: Path, bridge: bool) -> None:
    """Both release formats extract; the optional bridge yields an immutable old-client channel."""
    tree = fixture(tmp_path, bridge)
    asset = tmp_path / "release.tar.gz"
    archive(tree, asset)
    extracted = tmp_path / "extracted"
    extractor.extract(asset, extracted, "0.1.0")
    server = tmp_path / "server"
    publisher.prepare(extracted, server, "0.1.0")
    if not bridge:
        assert not server.exists()
        return
    channel = server / "concrete-updates"
    assert (channel / "latest" / "version").read_text() == "1.0.0\n"
    for target in extractor.TARGETS:
        expected = (tree / "0.1.0" / target / "concrete-update-bridge").read_bytes()
        assert (channel / "latest" / target / "concrete").read_bytes() == expected
    publisher.prepare(extracted, server, "0.1.0")
    assert (channel / "latest").readlink() == Path("1.0.0")


@pytest.mark.parametrize("damage", ["partial", "checksum", "symlink"])
def test_invalid_bridge_release_failure(tmp_path: Path, damage: str) -> None:
    """Incomplete, corrupt, and linked bridge assets fail the release allowlist."""
    tree = fixture(tmp_path)
    target = sorted(extractor.TARGETS)[0]
    binary = tree / "0.1.0" / target / "concrete-update-bridge"
    if damage == "partial":
        binary.unlink()
    elif damage == "checksum":
        binary.write_bytes(b"substituted payload")
    else:
        binary.unlink()
        binary.symlink_to("umbra")
    asset = tmp_path / "invalid.tar.gz"
    archive(tree, asset)
    with pytest.raises(SystemExit):
        extractor.extract(asset, tmp_path / "rejected", "0.1.0")


def test_immutable_bridge_release_failure(tmp_path: Path) -> None:
    """A different payload cannot replace a previously published bridge version."""
    tree = fixture(tmp_path)
    server = tmp_path / "server"
    publisher.prepare(tree, server, "0.1.0")
    target = sorted(extractor.TARGETS)[0]
    binary = tree / "0.1.0" / target / "concrete-update-bridge"
    binary.write_bytes(b"different verified release")
    binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + "  concrete-update-bridge\n")
    with pytest.raises(ValueError, match="immutable"):
        publisher.prepare(tree, server, "0.1.0")
    assert (server / "concrete-updates/latest").readlink() == Path("1.0.0")


def test_legacy_channel_downgrade_failure(tmp_path: Path) -> None:
    """Publishing an older bridge cannot roll the mutable pointer backward."""
    tree = fixture(tmp_path, bridge_version="2.0.0")
    server = tmp_path / "server"
    publisher.prepare(tree, server, "0.1.0")
    (tree / "0.1.0/concrete-update-version").write_text("1.0.0\n")
    with pytest.raises(ValueError, match="downgrade"):
        publisher.prepare(tree, server, "0.1.0")
    assert (server / "concrete-updates/latest").readlink() == Path("2.0.0")
