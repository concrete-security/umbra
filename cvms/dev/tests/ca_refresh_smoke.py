#!/usr/bin/env python3
"""Smoke test for the sandbox umbra-ca-refresh watcher (Part B / dynamic SC CA install)."""
import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

CA1 = b"-----BEGIN CERTIFICATE-----\nAAAAoldCA\n-----END CERTIFICATE-----\n"
CA2 = b"-----BEGIN CERTIFICATE-----\nBBBBrotatedCA\n-----END CERTIFICATE-----\n"
CA3 = b"-----BEGIN CERTIFICATE-----\nCCCCnewLaunchCA\n-----END CERTIFICATE-----\n"
ROOTS = b"-----BEGIN CERTIFICATE-----\nDISTROROOTS\n-----END CERTIFICATE-----\n"


def load_module():
    path = Path(__file__).resolve().parents[1] / "user-sandbox" / "umbra-ca-refresh.py"
    spec = importlib.util.spec_from_file_location("umbra_ca_refresh", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_config(m, temp: Path):
    return m.RefreshConfig(
        source_path=temp / "shared" / "security-cvm-ca.pem",
        binding_path=temp / "shared" / "security-cvm-ca.json",
        launch_ca_path=temp / "run" / "security-cvm-ca.launch.pem",
        bundle_path=temp / "run" / "ca-bundle.pem",
        sc_cert_path=temp / "run" / "security-cvm-ca.pem",
        system_roots_path=temp / "etc" / "roots.pem",
        security_cvm_fqdn="sc.example.com",
        interval_seconds=1.0,
        bootstrap_timeout_seconds=120.0,
    )


def publish(config, ca: bytes, fqdn: str = "sc.example.com") -> None:
    config.source_path.write_bytes(ca)
    config.binding_path.write_text(
        json.dumps(
            {
                "security_cvm_fqdn": fqdn,
                "ca_cert_sha256": hashlib.sha256(ca).hexdigest(),
                "launch_ca_cert_sha256": hashlib.sha256(config.launch_ca_path.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
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
        cfg.launch_ca_path.write_bytes(CA1)

        # No published CA yet → no-op.
        assert m.refresh_once(cfg) is False

        # A CA without its forwarder-owned binding is incomplete and ignored.
        cfg.source_path.write_bytes(CA1)
        assert m.refresh_once(cfg) is False

        # First bound CA published → installed into the bundle and the SC copy.
        publish(cfg, CA1)
        assert m.refresh_once(cfg) is True
        assert cfg.bundle_path.read_bytes() == ROOTS + CA1
        assert cfg.sc_cert_path.read_bytes() == CA1
        assert stat.S_IMODE(cfg.bundle_path.stat().st_mode) == 0o644
        assert stat.S_IMODE(cfg.sc_cert_path.stat().st_mode) == 0o444

        # Unchanged → no-op.
        assert m.refresh_once(cfg) is False

        # A torn rotation (new CA, old digest sidecar) keeps the last good trust
        # bundle. Once its authenticated binding arrives, replace rather than append.
        cfg.source_path.write_bytes(CA2)
        assert m.refresh_once(cfg) is False
        assert cfg.bundle_path.read_bytes() == ROOTS + CA1
        publish(cfg, CA2)
        assert m.refresh_once(cfg) is True
        bundle = cfg.bundle_path.read_bytes()
        assert CA2 in bundle
        assert CA1 not in bundle
        assert cfg.sc_cert_path.read_bytes() == CA2

        # Garbage published → ignored, bundle unchanged (fail safe).
        publish(cfg, b"not a certificate")
        assert m.refresh_once(cfg) is False
        assert cfg.bundle_path.read_bytes() == bundle

        # Sandbox restart prefers the valid forwarder-owned rotated CA over the
        # immutable launch baseline, preventing a temporary trust rollback.
        publish(cfg, CA2)
        m.install_ca(cfg, CA1)
        m.bootstrap(cfg, cfg.launch_ca_path)
        assert cfg.sc_cert_path.read_bytes() == CA2
        assert cfg.bundle_path.read_bytes() == ROOTS + CA2

        # Empty first boot uses the current attested launch CA.
        cfg.source_path.unlink()
        cfg.binding_path.unlink()
        assert m.select_bootstrap_ca(cfg, cfg.launch_ca_path) == ("launch", CA1)

        # A distribution bound to a previous FQDN also uses current launch
        # material; malformed same-volume state stays fail-closed for refresh.
        publish(cfg, CA2, fqdn="sc-old.example.com")
        assert m.select_bootstrap_ca(cfg, cfg.launch_ca_path) == ("launch", CA1)

        # A full update can change launch CA while retaining the same FQDN and
        # named volume. Baseline mismatch must use the new launch CA rather than
        # briefly re-installing the persisted CA from the old binding.
        publish(cfg, CA2)
        cfg.launch_ca_path.write_bytes(CA3)
        assert m.select_bootstrap_ca(cfg, cfg.launch_ca_path) == ("launch", CA3)
        assert m.refresh_once(cfg) is False

        cfg.binding_path.write_text("not json", encoding="utf-8")
        assert m.select_bootstrap_ca(cfg, cfg.launch_ca_path) is None

        # Probe failures are invalid, never equivalent to an empty first boot.
        class UnreadablePath:
            @staticmethod
            def lstat():
                raise PermissionError("denied")

        unreadable = SimpleNamespace(
            source_path=UnreadablePath(),
            binding_path=UnreadablePath(),
            security_cvm_fqdn="sc.example.com",
        )
        assert m.read_published_ca(unreadable) == ("invalid", None)

        # Invalid state keeps startup unhealthy only for the bounded bootstrap
        # window, then exits fail-closed instead of hanging provisioning forever.
        try:
            m.bootstrap(replace(cfg, bootstrap_timeout_seconds=0), cfg.launch_ca_path)
        except RuntimeError as exc:
            assert "timed out waiting" in str(exc)
        else:
            raise AssertionError("malformed persisted CA must time out fail-closed")

    print("ca_refresh_smoke: OK")


if __name__ == "__main__":
    main()
