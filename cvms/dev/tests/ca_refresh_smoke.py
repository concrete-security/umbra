#!/usr/bin/env python3
"""Smoke test for the sandbox concrete-ca-refresh watcher (Part B / dynamic SC CA install)."""
import importlib.util
import stat
import sys
import tempfile
from pathlib import Path

CA1 = b"-----BEGIN CERTIFICATE-----\nAAAAoldCA\n-----END CERTIFICATE-----\n"
CA2 = b"-----BEGIN CERTIFICATE-----\nBBBBrotatedCA\n-----END CERTIFICATE-----\n"
ROOTS = b"-----BEGIN CERTIFICATE-----\nDISTROROOTS\n-----END CERTIFICATE-----\n"


def load_module():
    path = Path(__file__).resolve().parents[1] / "user-sandbox" / "concrete-ca-refresh.py"
    spec = importlib.util.spec_from_file_location("concrete_ca_refresh", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_config(m, temp: Path):
    return m.RefreshConfig(
        source_path=temp / "shared" / "security-cvm-ca.pem",
        bundle_path=temp / "run" / "ca-bundle.pem",
        sc_cert_path=temp / "run" / "security-cvm-ca.pem",
        system_roots_path=temp / "etc" / "roots.pem",
        interval_seconds=1.0,
    )


def main():
    m = load_module()

    assert m.is_valid_ca_pem(CA1)
    assert not m.is_valid_ca_pem(b"not a certificate")
    assert not m.is_valid_ca_pem(b"\xff\xfe")
    assert m.compose_bundle(ROOTS, CA1) == ROOTS + CA1
    # Tolerates system roots without a trailing newline.
    assert m.compose_bundle(b"ROOTS", CA1) == b"ROOTS\n" + CA1

    with tempfile.TemporaryDirectory() as temp_name:
        temp = Path(temp_name)
        cfg = make_config(m, temp)
        cfg.system_roots_path.parent.mkdir(parents=True)
        cfg.system_roots_path.write_bytes(ROOTS)
        cfg.source_path.parent.mkdir(parents=True)
        cfg.sc_cert_path.parent.mkdir(parents=True)

        # No published CA yet → no-op.
        assert m.refresh_once(cfg) is False

        # First CA published → installed into the bundle and the SC copy.
        cfg.source_path.write_bytes(CA1)
        assert m.refresh_once(cfg) is True
        assert cfg.bundle_path.read_bytes() == ROOTS + CA1
        assert cfg.sc_cert_path.read_bytes() == CA1
        assert stat.S_IMODE(cfg.bundle_path.stat().st_mode) == 0o644
        assert stat.S_IMODE(cfg.sc_cert_path.stat().st_mode) == 0o444

        # Unchanged → no-op.
        assert m.refresh_once(cfg) is False

        # Rotated CA → replace, not append: the old CA must be gone from the bundle.
        cfg.source_path.write_bytes(CA2)
        assert m.refresh_once(cfg) is True
        bundle = cfg.bundle_path.read_bytes()
        assert CA2 in bundle
        assert CA1 not in bundle
        assert cfg.sc_cert_path.read_bytes() == CA2

        # Garbage published → ignored, bundle unchanged (fail safe).
        cfg.source_path.write_bytes(b"not a certificate")
        assert m.refresh_once(cfg) is False
        assert cfg.bundle_path.read_bytes() == bundle

    print("ca_refresh_smoke: OK")


if __name__ == "__main__":
    main()
