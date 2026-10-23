"""Bounded fixtures for the pip vendor exception's absent-code guarantees."""

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile

CHECKER = Path(__file__).with_name("check-pip-vendor.py")
RUN_CHECK = "import pathlib,runpy,sys; runpy.run_path(sys.argv[1])['check_image'](pathlib.Path(sys.argv[2]))"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def metadata(packages: Path, name: str, version: str, directory: str | None = None) -> Path:
    path = packages / (directory or f"{name}-{version}.dist-info") / "METADATA"
    write(path, f"Name: {name}\nVersion: {version}\n")
    return path


def fixture(root: Path) -> tuple[Path, Path, Path]:
    packages = root / "usr/local/lib/python3.12/site-packages"
    app = root / "app/.venv/lib/python3.12/site-packages"
    pip = packages / "pip"
    metadata(packages, "pip", "26.2.2")
    write(pip / "__init__.py", '__version__ = "26.2.2"\n')
    versions = {"msgpack": "1.1.2", "setuptools": "70.3.0", "urllib3": "2.8.0"}
    write(pip / "_vendor/vendor.txt", "".join(f"{name}=={version}\n" for name, version in versions.items()))
    write(pip / "_vendor/bom.cdx.json", json.dumps({"components": [{"name": name, "version": version} for name, version in versions.items()]}))
    for name in ["COPYING", "exceptions.py", "ext.py", "fallback.py"]:
        write(pip / "_vendor/msgpack" / name, "")
    write(pip / "_vendor/msgpack/__init__.py", '__version__ = "1.1.2"\n')
    write(pip / "_vendor/pkg_resources/__init__.py", "")
    metadata(app, "msgpack", "1.2.1")
    metadata(app, "setuptools", "78.1.1")
    return packages, app, pip


def check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", RUN_CHECK, str(CHECKER), str(root)],
        capture_output=True, text=True, timeout=5, check=False,
    )


class PipVendorGuardTests(unittest.TestCase):
    def test_reviewed_vendor_subset_success(self) -> None:
        """The reviewed subset and independently fixed app distributions pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            result = check(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_implementation_failure(self) -> None:
        """Real vulnerable installations and implementation drift fail within five seconds."""
        for variant in ["native", "package-index", "renamed-class", "bytecode", "global-real", "app-real", "duplicate-real", "egg-file", "egg-directory", "bad-metadata", "pip-drift", "vendor-drift", "bundled-native", "target-real", "symlink-metadata", "zipped-egg"]:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                packages, app, pip = fixture(root)
                vendor = pip / "_vendor"
                if variant == "native":
                    write(vendor / "msgpack/_cmsgpack.cpython-312-x86_64-linux-gnu.so", "native fixture")
                elif variant == "package-index":
                    write(vendor / "setuptools/package_index.py", "class PackageIndex: pass\n")
                elif variant == "renamed-class":
                    write(vendor / "pkg_resources/renamed.py", "class PackageIndex: pass\n")
                elif variant == "bytecode":
                    write(vendor / "pkg_resources/__pycache__/package_index.cpython-312.pyc", "bytecode fixture")
                elif variant == "global-real":
                    metadata(packages, "setuptools", "70.3.0")
                elif variant == "app-real":
                    metadata(app, "msgpack", "1.1.2")
                elif variant == "duplicate-real":
                    metadata(app, "setuptools", "70.3.0", "z-duplicate.dist-info")
                elif variant == "egg-file":
                    write(app / "msgpack.egg-info", "Name: msgpack\nVersion: 1.1.2\n")
                elif variant == "egg-directory":
                    write(app / "setuptools.egg-info/PKG-INFO", "Name: setuptools\nVersion: 70.3.0\n")
                elif variant == "bad-metadata":
                    write(app / "unknown.dist-info/METADATA", "Name: msgpack\n")
                elif variant == "pip-drift":
                    metadata(packages, "pip", "26.2.3", "pip-26.2.2.dist-info")
                elif variant == "vendor-drift":
                    write(vendor / "msgpack/__init__.py", '__version__ = "1.2.0"\n')
                elif variant == "zipped-egg":
                    with zipfile.ZipFile(app / "setuptools.egg", "w") as archive:
                        archive.writestr("EGG-INFO/PKG-INFO", "Name: setuptools\nVersion: 70.3.0\n")
                elif variant == "target-real":
                    metadata(root / "opt/vendor", "msgpack", "1.1.2")
                elif variant == "symlink-metadata":
                    source = root / "opt/metadata"
                    write(source / "METADATA", "Name: setuptools\nVersion: 70.3.0\n")
                    (app / "linked.dist-info").symlink_to(source, target_is_directory=True)
                elif variant == "bundled-native":
                    wheel = root / "usr/local/lib/python3.12/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl"
                    wheel.parent.mkdir(parents=True)
                    with zipfile.ZipFile(wheel, "w") as archive:
                        for path in pip.rglob("*"):
                            if path.is_file():
                                archive.write(path, "pip/" + path.relative_to(pip).as_posix())
                        archive.writestr("pip/_vendor/msgpack/_cmsgpack.so", b"native fixture")
                result = check(root)
                self.assertNotEqual(result.returncode, 0, variant)
                reason = {
                    "native": "native pip vendor module",
                    "package-index": "PackageIndex implementation",
                    "renamed-class": "PackageIndex implementation",
                    "bytecode": "PackageIndex implementation",
                    "global-real": "real installed setuptools 70.3.0",
                    "app-real": "real installed msgpack 1.1.2",
                    "duplicate-real": "real installed setuptools 70.3.0",
                    "egg-file": "real installed msgpack 1.1.2",
                    "egg-directory": "real installed setuptools 70.3.0",
                    "bad-metadata": "incomplete package metadata",
                    "pip-drift": "pip version drift",
                    "vendor-drift": "reviewed pure-Python subset",
                    "bundled-native": "reviewed pure-Python subset",
                    "target-real": "real installed msgpack 1.1.2",
                    "symlink-metadata": "real installed setuptools 70.3.0",
                    "zipped-egg": "real installed setuptools 70.3.0",
                }[variant]
                self.assertIn(reason, result.stderr)


if __name__ == "__main__":
    unittest.main()
