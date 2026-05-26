from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
from pathlib import Path
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


DEFAULT_CA_COMMON_NAME = "Concrete Security CVM Root CA"
DEFAULT_CA_VALIDITY_DAYS = 365


class CAExportUnauthorized(PermissionError):
    pass


@dataclass(frozen=True)
class InMemoryRootCA:
    private_key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def ca_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    def export_ca_pem(self, *, supplied_token: str, ca_export_token: str) -> bytes:
        if not hmac.compare_digest(supplied_token, ca_export_token):
            raise CAExportUnauthorized("invalid CA export bearer")
        return self.ca_pem


def generate_root_ca(
    *,
    common_name: str = DEFAULT_CA_COMMON_NAME,
    now: datetime | None = None,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
) -> InMemoryRootCA:
    if validity_days <= 0:
        raise ValueError("validity_days must be positive")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    issued_at = issued_at.astimezone(timezone.utc)
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issued_at - timedelta(minutes=1))
        .not_valid_after(issued_at + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA384())
    )
    return InMemoryRootCA(private_key=key, certificate=cert)


def write_mitmproxy_ca_files(ca: InMemoryRootCA, directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(stat.S_IRWXU)
    private_bundle = ca.private_key_pem + ca.ca_pem
    private_bundle_path = directory / "mitmproxy-ca.pem"
    public_cert_path = directory / "mitmproxy-ca-cert.pem"
    private_bundle_path.write_bytes(private_bundle)
    private_bundle_path.chmod(stat.S_IRUSR)
    public_cert_path.write_bytes(ca.ca_pem)
    public_cert_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
