from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

from concrete_security_cvm.ca import CAExportUnauthorized, generate_root_ca


def test_generate_root_ca_uses_p384_ca_certificate() -> None:
    ca = generate_root_ca(now=datetime(2026, 5, 16, 6, 0, tzinfo=timezone.utc))

    assert isinstance(ca.private_key.curve, ec.SECP384R1)
    cert = x509.load_pem_x509_certificate(ca.ca_pem)
    assert cert.subject == cert.issuer
    assert cert.not_valid_before_utc <= datetime(2026, 5, 16, 6, 0, tzinfo=timezone.utc)
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
