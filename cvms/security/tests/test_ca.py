from datetime import datetime, timezone
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

from concrete_security_cvm.ca import CAExportUnauthorized, generate_root_ca, write_mitmproxy_ca_files


def test_generate_root_ca_uses_p384_ca_certificate() -> None:
    issued_at = datetime(2026, 5, 16, 6, 0, tzinfo=timezone.utc)
    ca = generate_root_ca(now=issued_at)

    assert isinstance(ca.private_key.curve, ec.SECP384R1)
    cert = x509.load_pem_x509_certificate(ca.ca_pem)
    assert cert.subject == cert.issuer
    assert cert.not_valid_before_utc <= datetime(2026, 5, 16, 6, 0, tzinfo=timezone.utc)
    assert cert.not_valid_after_utc == issued_at.replace(year=2027)
    basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert basic_constraints.ca is True
    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert key_usage.key_cert_sign is True
    assert key_usage.crl_sign is True
    assert b"PRIVATE KEY" not in ca.ca_pem


def test_export_ca_pem_requires_exact_bearer() -> None:
    ca = generate_root_ca()

    assert ca.export_ca_pem(supplied_token="correct", ca_export_token="correct") == ca.ca_pem
    with pytest.raises(CAExportUnauthorized):
        ca.export_ca_pem(supplied_token="wrong", ca_export_token="correct")


def test_write_mitmproxy_ca_files_uses_tmpfs_friendly_private_modes(tmp_path) -> None:
    ca = generate_root_ca()

    write_mitmproxy_ca_files(ca, tmp_path / "mitmproxy")

    directory = tmp_path / "mitmproxy"
    private_bundle = directory / "mitmproxy-ca.pem"
    public_cert = directory / "mitmproxy-ca-cert.pem"
    assert private_bundle.read_bytes() == ca.private_key_pem + ca.ca_pem
    assert public_cert.read_bytes() == ca.ca_pem
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_bundle.stat().st_mode) == 0o400
    assert stat.S_IMODE(public_cert.stat().st_mode) == 0o444
