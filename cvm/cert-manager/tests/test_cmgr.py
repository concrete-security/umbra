"""
Test suite for Certificate Manager Service

This module contains comprehensive tests for all certificate manager components:
- CertificateManager: Main class handling cert creation, validation, and renewal
- Supervisor: Nginx configuration and restart functionality
- CertbotWrapper: Let's Encrypt certificate provisioning

External dependencies such as Dstack and Let's Encrypt are mocked.
"""

import os
import tempfile
import subprocess
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from cert_manager.cmgr import CertificateManager
from cert_manager.supervisor import Supervisor
from cert_manager.certbot import CertbotWrapper


# Test fixtures and helper functions
@pytest.fixture
def temp_dir():
    """Create a temporary directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_private_key():
    """Generate a test EC private key."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def mock_certificate(mock_private_key):
    """Generate a test self-signed certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(mock_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
        .sign(mock_private_key, hashes.SHA256())
    )
    return cert


@pytest.fixture
def mock_letsencrypt_staging_cert(mock_private_key):
    """Generate a test Let's Encrypt staging certificate."""
    # Create issuer with "staging" in CN to simulate staging cert
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "(STAGING) Fake LE Intermediate X1"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(mock_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .sign(mock_private_key, hashes.SHA256())
    )
    return cert


@pytest.fixture
def mock_letsencrypt_prod_cert(mock_private_key):
    """Generate a test Let's Encrypt production certificate."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "E8"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(mock_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .sign(mock_private_key, hashes.SHA256())
    )
    return cert


@pytest.fixture
def expired_certificate(mock_private_key):
    """Generate an expired certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(mock_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=100))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))  # Expired yesterday
        .sign(mock_private_key, hashes.SHA256())
    )
    return cert


def create_cert_manager(temp_cert_dir, dev_mode=True, letsencrypt_staging=True):
    """Helper function to create a CertificateManager instance for testing."""
    manager = CertificateManager(
        domain="test.example.com",
        dev_mode=dev_mode,
        cert_email="test@example.com",
        letsencrypt_staging=letsencrypt_staging,
        letsencrypt_account_version="v1",
        cert_path=temp_cert_dir,
        acme_path=temp_cert_dir / "acme",
    )
    return manager


# CertificateManager Tests
class TestCertificateManager:
    """Test suite for the main CertificateManager class."""

    def test_init_dev_mode(self, temp_dir):
        """Test CertificateManager initialization in dev mode."""
        manager = create_cert_manager(temp_dir, dev_mode=True)

        assert manager.domain == "test.example.com"
        assert manager.dev_mode
        assert manager.cert_email == "test@example.com"
        assert manager.letsencrypt_staging
        assert manager.letsencrypt_account_version == "v1"

    def test_init_staging_mode(self, temp_dir):
        """Test CertificateManager initialization in staging mode."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=True)

        assert not manager.dev_mode
        assert manager.letsencrypt_staging

    def test_init_production_mode(self, temp_dir):
        """Test CertificateManager initialization in production mode."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        assert not manager.dev_mode
        assert not manager.letsencrypt_staging

    @patch("cert_manager.cmgr.DstackClient")
    def test_get_deterministic_key_material_dev_mode(self, mock_dstack, temp_dir):
        """Test key material generation in dev mode."""
        manager = create_cert_manager(temp_dir, dev_mode=True)

        key_material = manager.get_deterministic_key_material("test-key")

        assert key_material == b"\x01" * 32
        mock_dstack.assert_not_called()  # Should not call dstack in dev mode

    @patch("cert_manager.cmgr.DstackClient")
    def test_get_deterministic_key_material_production(self, mock_dstack, temp_dir):
        """Test key material generation in production mode."""
        # Mock dstack client behavior
        mock_client = Mock()
        mock_result = Mock()
        mock_result.decode_key.return_value = b"\x02" * 32
        mock_client.get_key.return_value = mock_result
        mock_dstack.return_value = mock_client

        manager = create_cert_manager(temp_dir, dev_mode=False)

        key_material = manager.get_deterministic_key_material("test-key")

        assert key_material == b"\x02" * 32
        mock_dstack.assert_called_once()
        mock_client.get_key.assert_called_once_with("test-key")

    @patch("cert_manager.cmgr.DstackClient")
    def test_get_deterministic_key_material_failure(self, mock_dstack, temp_dir):
        """Test key material generation failure handling."""
        mock_dstack.side_effect = Exception("Dstack connection failed")

        manager = create_cert_manager(temp_dir, dev_mode=False)

        with pytest.raises(Exception, match="Dstack connection failed"):
            manager.get_deterministic_key_material("test-key")

    def test_derive_ec_privatekey_from_key_material(self, temp_dir):
        """Test EC private key derivation from key material."""
        manager = create_cert_manager(temp_dir)
        key_material = b"\x01" * 32

        private_key = manager.derive_ec_privatekey_from_key_material(key_material)

        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP256R1)

    @patch.object(CertificateManager, "get_deterministic_key_material")
    def test_generate_deterministic_key(self, mock_get_material, temp_dir):
        """Test deterministic key generation."""
        mock_get_material.return_value = b"\x03" * 32
        manager = create_cert_manager(temp_dir)

        private_key = manager.generate_deterministic_key("test-path")

        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        mock_get_material.assert_called_once_with("test-path")

    def test_create_self_signed_cert(self, temp_dir, mock_private_key):
        """Test self-signed certificate creation."""
        manager = create_cert_manager(temp_dir)

        cert_chain = manager.create_self_signed_cert(mock_private_key)

        assert isinstance(cert_chain, list)
        assert len(cert_chain) == 1
        cert = cert_chain[0]
        assert isinstance(cert, x509.Certificate)
        assert cert.subject == cert.issuer  # Self-signed

        # Check domain in SAN extension
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = [name.value for name in san_ext.value]
        assert "test.example.com" in dns_names
        assert "localhost" in dns_names

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch("cert_manager.cmgr.CertbotWrapper")
    def test_create_lets_encrypt_cert(
        self,
        mock_certbot_class,
        mock_gen_key,
        temp_dir,
        mock_private_key,
        mock_letsencrypt_staging_cert,
    ):
        """Test Let's Encrypt certificate creation."""
        # Setup mocks
        mock_gen_key.return_value = mock_private_key
        mock_certbot = Mock()
        mock_certbot.obtain_certificate_with_csr.return_value = (
            mock_letsencrypt_staging_cert.public_bytes(Encoding.PEM)
        )
        mock_certbot_class.return_value = mock_certbot

        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=True)

        cert_chain = manager.create_lets_encrypt_cert(mock_private_key)

        assert isinstance(cert_chain, list)
        assert len(cert_chain) == 1  # Mock returns a single cert
        cert = cert_chain[0]
        assert isinstance(cert, x509.Certificate)
        mock_certbot_class.assert_called_once_with(staging=True)
        mock_certbot.obtain_certificate_with_csr.assert_called_once()
        mock_gen_key.assert_called_once()

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch("cert_manager.cmgr.CertbotWrapper")
    def test_create_lets_encrypt_cert_fullchain(
        self,
        mock_certbot_class,
        mock_gen_key,
        temp_dir,
        mock_private_key,
    ):
        """Test Let's Encrypt certificate creation with fullchain (multiple certificates)."""
        # Setup mocks
        mock_gen_key.return_value = mock_private_key
        mock_certbot = Mock()

        # Create a mock fullchain with 3 certificates
        leaf_cert = self._create_test_certificate(
            "example.com", "Intermediate CA", mock_private_key
        )
        intermediate_cert = self._create_test_certificate(
            "Intermediate CA", "Root CA", mock_private_key
        )
        root_cert = self._create_test_certificate("Root CA", "Root CA", mock_private_key)

        # Combine certificates into a fullchain PEM
        fullchain_pem = (
            leaf_cert.public_bytes(Encoding.PEM)
            + intermediate_cert.public_bytes(Encoding.PEM)
            + root_cert.public_bytes(Encoding.PEM)
        )

        mock_certbot.obtain_certificate_with_csr.return_value = fullchain_pem
        mock_certbot_class.return_value = mock_certbot

        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        cert_chain = manager.create_lets_encrypt_cert(mock_private_key)

        # Verify we get all certificates in the chain
        assert isinstance(cert_chain, list)
        assert len(cert_chain) == 3, f"Expected 3 certificates in fullchain, got {len(cert_chain)}"

        # Verify each certificate is correct
        for i, cert in enumerate(cert_chain):
            assert isinstance(cert, x509.Certificate)

        # Verify order: leaf, intermediate, root
        leaf_cn = cert_chain[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        intermediate_cn = cert_chain[1].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        root_cn = cert_chain[2].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert leaf_cn == "example.com"
        assert intermediate_cn == "Intermediate CA"
        assert root_cn == "Root CA"

        mock_certbot_class.assert_called_once_with(staging=False)
        mock_certbot.obtain_certificate_with_csr.assert_called_once()
        mock_gen_key.assert_called_once()

    def test_save_certificate_and_key(self, temp_dir, mock_certificate, mock_private_key):
        """Test saving certificate and key to files."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        # Check files were created
        cert_file = temp_dir / "cert.pem"
        key_file = temp_dir / "key.pem"

        assert cert_file.exists()
        assert key_file.exists()

        # Verify file permissions on key file
        assert oct(key_file.stat().st_mode)[-3:] == "600"

    def test_save_certificate_chain_fullchain(self, temp_dir, mock_private_key):
        """Test saving a certificate chain (fullchain) to files."""
        manager = create_cert_manager(temp_dir)

        # Create a mock certificate chain with 3 certificates (leaf, intermediate, root)
        leaf_cert = self._create_test_certificate(
            "example.com", "Intermediate CA", mock_private_key
        )
        intermediate_cert = self._create_test_certificate(
            "Intermediate CA", "Root CA", mock_private_key
        )
        root_cert = self._create_test_certificate(
            "Root CA", "Root CA", mock_private_key
        )  # Self-signed root

        cert_chain = [leaf_cert, intermediate_cert, root_cert]

        manager.save_certificate_and_key(cert_chain, mock_private_key)

        # Check files were created
        cert_file = temp_dir / "cert.pem"
        key_file = temp_dir / "key.pem"

        assert cert_file.exists()
        assert key_file.exists()

        # Read back the certificate chain and verify all certificates are stored
        with open(cert_file, "rb") as f:
            loaded_certs = x509.load_pem_x509_certificates(f.read())

        # Verify we have all 3 certificates in the correct order
        assert len(loaded_certs) == 3, f"Expected 3 certificates, got {len(loaded_certs)}"

        # Verify the order is preserved (leaf, intermediate, root)
        leaf_cn = loaded_certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        intermediate_cn = (
            loaded_certs[1].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
        root_cn = loaded_certs[2].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert leaf_cn == "example.com"
        assert intermediate_cn == "Intermediate CA"
        assert root_cn == "Root CA"

        # Verify issuer relationships
        leaf_issuer_cn = loaded_certs[0].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        intermediate_issuer_cn = (
            loaded_certs[1].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
        root_issuer_cn = loaded_certs[2].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert leaf_issuer_cn == "Intermediate CA"
        assert intermediate_issuer_cn == "Root CA"
        assert root_issuer_cn == "Root CA"  # Self-signed root

        # Verify file permissions on key file
        assert oct(key_file.stat().st_mode)[-3:] == "600"

    def _create_test_certificate(self, subject_cn: str, issuer_cn: str, private_key):
        """Helper method to create a test certificate with specified subject and issuer."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(subject_cn)])
                if subject_cn != "Intermediate CA" and subject_cn != "Root CA"
                else x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        return cert

    def test_is_cert_valid_no_files(self, temp_dir):
        """Test certificate validation when files don't exist."""
        manager = create_cert_manager(temp_dir)

        assert not manager.is_cert_valid()

    def test_is_cert_valid_expired(self, temp_dir, expired_certificate, mock_private_key):
        """Test certificate validation with expired certificate."""
        manager = create_cert_manager(temp_dir)

        # Save expired certificate
        manager.save_certificate_and_key(expired_certificate, mock_private_key)

        assert not manager.is_cert_valid()

    def test_is_cert_valid_expiring_soon(self, temp_dir, mock_private_key):
        """Test certificate validation with certificate expiring soon."""
        manager = create_cert_manager(temp_dir)

        # Create certificate expiring in 20 days (less than 30-day threshold)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(mock_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=20))  # Expires in 20 days
            .sign(mock_private_key, hashes.SHA256())
        )

        manager.save_certificate_and_key(cert, mock_private_key)

        assert not manager.is_cert_valid()

    def test_is_cert_valid_good_cert(self, temp_dir, mock_certificate, mock_private_key):
        """Test certificate validation with valid certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        assert manager.is_cert_valid()

    def test_is_cert_self_signed_true(self, temp_dir, mock_certificate, mock_private_key):
        """Test detection of self-signed certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        assert manager.is_cert_self_signed()

    def test_is_prod_cert_self_signed(self, temp_dir, mock_letsencrypt_prod_cert, mock_private_key):
        """Test detection of non-self-signed certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_letsencrypt_prod_cert, mock_private_key)

        assert not manager.is_cert_self_signed()

    def test_is_staging_cert_self_signed(
        self, temp_dir, mock_letsencrypt_staging_cert, mock_private_key
    ):
        """Test detection of non-self-signed certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_letsencrypt_staging_cert, mock_private_key)

        assert not manager.is_cert_self_signed()

    def test_is_cert_self_signed_no_file(self, temp_dir):
        """Test self-signed detection when no certificate file exists."""
        manager = create_cert_manager(temp_dir)

        assert not manager.is_cert_self_signed()

    def test_is_cert_letsencrypt_staging_true(
        self, temp_dir, mock_letsencrypt_staging_cert, mock_private_key
    ):
        """Test detection of Let's Encrypt staging certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_letsencrypt_staging_cert, mock_private_key)

        assert manager.is_cert_letsencrypt_staging()

    def test_is_prod_cert_staging_false(
        self, temp_dir, mock_letsencrypt_prod_cert, mock_private_key
    ):
        """Test detection of non-staging Let's Encrypt certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_letsencrypt_prod_cert, mock_private_key)

        assert not manager.is_cert_letsencrypt_staging()

    def test_is_self_signed_cert_staging_false(self, temp_dir, mock_certificate, mock_private_key):
        """Test detection of non-staging Let's Encrypt certificate."""
        manager = create_cert_manager(temp_dir)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        assert not manager.is_cert_letsencrypt_staging()

    def test_delete_certificate_files(self, temp_dir, mock_certificate, mock_private_key):
        """Test deletion of certificate files."""
        manager = create_cert_manager(temp_dir)

        # First save some files
        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        cert_file = temp_dir / "cert.pem"
        key_file = temp_dir / "key.pem"

        assert cert_file.exists()
        assert key_file.exists()

        # Now delete them
        manager.delete_certificate_files()

        assert not cert_file.exists()
        assert not key_file.exists()

    def test_delete_certificate_files_no_files(self, temp_dir):
        """Test deletion when no certificate files exist."""
        manager = create_cert_manager(temp_dir)

        # Should not raise an error
        manager.delete_certificate_files()

    @patch("cert_manager.cmgr.DstackClient")
    def test_emit_new_cert_event_dev_mode(
        self, mock_dstack, temp_dir, mock_certificate, mock_private_key
    ):
        """Test new certificate event emission in dev mode."""
        manager = create_cert_manager(temp_dir, dev_mode=True)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        # Should not raise an error and should not call dstack
        manager.emit_new_cert_event()

        mock_dstack.assert_not_called()

    @patch("cert_manager.cmgr.DstackClient")
    def test_emit_new_cert_event_production(
        self, mock_dstack, temp_dir, mock_certificate, mock_private_key
    ):
        """Test new certificate event emission in production mode."""
        mock_client = Mock()
        mock_dstack.return_value = mock_client

        manager = create_cert_manager(temp_dir, dev_mode=False)

        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        manager.emit_new_cert_event()

        mock_dstack.assert_called_once()
        mock_client.emit_event.assert_called_once()
        args, _ = mock_client.emit_event.call_args
        assert args[0] == "New TLS Certificate"
        assert len(args[1]) == 64  # SHA256 hash length

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch.object(CertificateManager, "create_self_signed_cert")
    @patch.object(CertificateManager, "save_certificate_and_key")
    @patch.object(CertificateManager, "emit_new_cert_event")
    def test_create_or_renew_certificate_dev_mode(
        self,
        mock_emit,
        mock_save,
        mock_create_self,
        mock_gen_key,
        temp_dir,
        mock_private_key,
        mock_certificate,
    ):
        """Test certificate creation/renewal in dev mode."""
        mock_gen_key.return_value = mock_private_key
        mock_create_self.return_value = mock_certificate

        manager = create_cert_manager(temp_dir, dev_mode=True)

        manager.create_or_renew_certificate()

        mock_gen_key.assert_called_once_with("cert/debug/test.example.com/v1")
        mock_create_self.assert_called_once_with(mock_private_key)
        mock_save.assert_called_once_with(mock_certificate, mock_private_key)
        mock_emit.assert_called_once()

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch.object(CertificateManager, "create_lets_encrypt_cert")
    @patch.object(CertificateManager, "save_certificate_and_key")
    @patch.object(CertificateManager, "emit_new_cert_event")
    def test_create_or_renew_certificate_production_success(
        self,
        mock_emit,
        mock_save,
        mock_create_le,
        mock_gen_key,
        temp_dir,
        mock_private_key,
        mock_letsencrypt_prod_cert,
    ):
        """Test certificate creation/renewal in production mode - success."""
        mock_gen_key.return_value = mock_private_key
        mock_create_le.return_value = mock_letsencrypt_prod_cert

        manager = create_cert_manager(temp_dir, dev_mode=False)

        manager.create_or_renew_certificate()

        mock_gen_key.assert_called_once_with("cert/letsencrypt/test.example.com/v1")
        mock_create_le.assert_called_once_with(mock_private_key)
        mock_save.assert_called_once_with(mock_letsencrypt_prod_cert, mock_private_key)
        mock_emit.assert_called_once()

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch.object(CertificateManager, "create_lets_encrypt_cert")
    @patch.object(CertificateManager, "save_certificate_and_key")
    @patch.object(CertificateManager, "emit_new_cert_event")
    @patch("time.sleep")  # Mock sleep to speed up test
    def test_create_or_renew_certificate_production_retry(
        self,
        mock_sleep,
        mock_emit,
        mock_save,
        mock_create_le,
        mock_gen_key,
        temp_dir,
        mock_private_key,
        mock_letsencrypt_prod_cert,
    ):
        """Test certificate creation/renewal with retries."""
        mock_gen_key.return_value = mock_private_key
        # First two calls fail, third succeeds
        mock_create_le.side_effect = [
            Exception("Network error"),
            Exception("Rate limit"),
            mock_letsencrypt_prod_cert,  # Success
        ]

        manager = create_cert_manager(temp_dir, dev_mode=False)

        # Should not raise exception
        manager.create_or_renew_certificate()

        assert mock_create_le.call_count == 3
        assert mock_sleep.call_count == 2  # Two retries
        mock_save.assert_called_once()
        mock_emit.assert_called_once()

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch.object(CertificateManager, "create_lets_encrypt_cert")
    @patch("time.sleep")
    def test_create_or_renew_certificate_production_max_retries(
        self, mock_sleep, mock_create_le, mock_gen_key, temp_dir, mock_private_key
    ):
        """Test certificate creation/renewal with max retries exceeded."""
        mock_gen_key.return_value = mock_private_key
        mock_create_le.side_effect = Exception("Persistent error")

        manager = create_cert_manager(temp_dir, dev_mode=False)

        with pytest.raises(Exception, match="Persistent error"):
            manager.create_or_renew_certificate()

        assert mock_create_le.call_count == 4  # Initial + 3 retries
        assert mock_sleep.call_count == 3  # 3 retries


# Supervisor Tests
class TestSupervisor:
    """Test suite for the Supervisor class."""

    def test_init_default_paths(self):
        """Test Supervisor initialization with default paths."""
        supervisor = Supervisor()

        assert os.path.realpath(supervisor.supervisor_conf_path) == os.path.realpath(
            "/etc/supervisor/conf.d/supervisord.conf"
        )
        assert os.path.realpath(supervisor.nginx_conf_path) == os.path.realpath(
            "/etc/nginx/conf.d/default.conf"
        )
        assert os.path.realpath(supervisor.nginx_base_conf_path) == os.path.realpath(
            "./nginx_conf/base.conf"
        )
        assert os.path.realpath(supervisor.nginx_https_conf_path) == os.path.realpath(
            "./nginx_conf/https.conf"
        )

    def test_init_custom_paths(self):
        """Test Supervisor initialization with custom paths."""
        supervisor = Supervisor(
            supervisor_conf_path="/custom/supervisor.conf",
            nginx_conf_path="/custom/nginx.conf",
            nginx_base_conf_path="/custom/base.conf",
            nginx_https_conf_path="/custom/https.conf",
        )

        assert supervisor.supervisor_conf_path == "/custom/supervisor.conf"
        assert supervisor.nginx_conf_path == "/custom/nginx.conf"
        assert supervisor.nginx_base_conf_path == "/custom/base.conf"
        assert supervisor.nginx_https_conf_path == "/custom/https.conf"

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_restart_nginx_success(self, mock_run, mock_exists):
        """Test successful nginx restart."""
        mock_exists.return_value = True
        mock_result = Mock()
        mock_result.stdout = "nginx: restarted"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        supervisor = Supervisor()

        # Should not raise exception
        supervisor.restart_nginx()

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        expected_cmd = [
            "supervisorctl",
            "-c",
            "/etc/supervisor/conf.d/supervisord.conf",
            "restart",
            "nginx",
        ]
        assert args[0] == expected_cmd
        assert kwargs["check"]
        assert kwargs["timeout"] == 30
        assert kwargs["capture_output"]

    @patch("os.path.exists")
    def test_restart_nginx_config_not_found(self, mock_exists):
        """Test nginx restart when supervisor config doesn't exist."""
        mock_exists.return_value = False

        supervisor = Supervisor()

        with pytest.raises(Exception, match="Supervisor configuration file not found"):
            supervisor.restart_nginx()

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_restart_nginx_command_failure(self, mock_run, mock_exists):
        """Test nginx restart command failure."""
        mock_exists.return_value = True
        mock_run.side_effect = subprocess.CalledProcessError(1, "supervisorctl", stderr="Error")

        supervisor = Supervisor()

        with pytest.raises(Exception, match="Nginx restart failed"):
            supervisor.restart_nginx()

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_restart_nginx_timeout(self, mock_run, mock_exists):
        """Test nginx restart timeout."""
        mock_exists.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired("supervisorctl", 30)

        supervisor = Supervisor()

        with pytest.raises(Exception, match="Nginx restart command timed out"):
            supervisor.restart_nginx()

    @patch.object(Supervisor, "restart_nginx")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="base config content")
    def test_setup_nginx_base_config(self, mock_file, mock_exists, mock_restart):
        """Test setting up nginx base configuration."""
        mock_exists.return_value = True

        supervisor = Supervisor()

        supervisor.setup_nginx_base_config()

        # Verify files were opened for reading and writing
        assert mock_file.call_count >= 2  # At least read and write
        mock_restart.assert_called_once()

    @patch.object(Supervisor, "restart_nginx")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="config content")
    def test_setup_nginx_https_config(self, mock_file, mock_exists, mock_restart):
        """Test setting up nginx HTTPS configuration."""
        mock_exists.return_value = True

        supervisor = Supervisor()

        supervisor.setup_nginx_https_config()

        # Verify files were opened for reading and writing
        assert mock_file.call_count >= 3  # Read base, read https, write combined
        mock_restart.assert_called_once()

    @patch("os.path.exists")
    def test_setup_nginx_base_config_file_not_found(self, mock_exists):
        """Test setup nginx base config when base config file doesn't exist."""
        mock_exists.return_value = False

        supervisor = Supervisor()

        with pytest.raises(Exception, match="Base nginx configuration not found"):
            supervisor.setup_nginx_base_config()

    @patch("os.path.exists")
    def test_setup_nginx_https_config_base_file_not_found(self, mock_exists):
        """Test setup nginx HTTPS config when base config file doesn't exist."""
        mock_exists.side_effect = lambda path: False if "base.conf" in path else True

        supervisor = Supervisor()

        with pytest.raises(Exception, match="Base nginx configuration not found"):
            supervisor.setup_nginx_https_config()

    @patch("os.path.exists")
    def test_setup_nginx_https_config_https_file_not_found(self, mock_exists):
        """Test setup nginx HTTPS config when HTTPS config file doesn't exist."""
        mock_exists.side_effect = lambda path: False if "https.conf" in path else True

        supervisor = Supervisor()

        with pytest.raises(Exception, match="HTTPS nginx configuration not found"):
            supervisor.setup_nginx_https_config()

    @patch.object(Supervisor, "restart_nginx")
    def test_setup_nginx_https_config_output_correct(self, mock_restart, temp_dir):
        """Test that HTTPS configuration correctly combines base and HTTPS configs."""

        # Create test config files
        base_config_path = temp_dir / "base.conf"
        https_config_path = temp_dir / "https.conf"
        output_config_path = temp_dir / "nginx.conf"

        base_config = "# Base configuration\nserver { listen 80; }"
        https_config = "# HTTPS configuration\nserver { listen 443 ssl; }"
        expected_combined = base_config + "\n" + https_config

        # Write the input config files
        base_config_path.write_text(base_config)
        https_config_path.write_text(https_config)

        # Create supervisor with custom paths
        supervisor = Supervisor(
            nginx_conf_path=str(output_config_path),
            nginx_base_conf_path=str(base_config_path),
            nginx_https_conf_path=str(https_config_path),
        )

        supervisor.setup_nginx_https_config()

        # Read the actual output file and verify contents
        actual_output = output_config_path.read_text()
        assert actual_output == expected_combined
        mock_restart.assert_called_once()


# CertbotWrapper Tests
class TestCertbotWrapper:
    """Test suite for the CertbotWrapper class."""

    def test_init_staging(self):
        """Test CertbotWrapper initialization for staging."""
        wrapper = CertbotWrapper(staging=True)

        assert wrapper.staging
        assert "staging" in wrapper.server_url.lower()

    def test_init_production(self):
        """Test CertbotWrapper initialization for production."""
        wrapper = CertbotWrapper(staging=False)

        assert not wrapper.staging
        assert "staging" not in wrapper.server_url.lower()

    @patch("subprocess.run")
    @patch("tempfile.TemporaryDirectory")
    @patch("os.path.exists")
    def test_obtain_certificate_with_csr_success(self, mock_exists, mock_tempdir, mock_run):
        """Test successful certificate obtaining with CSR."""
        # Setup mock temporary directory
        temp_path = Path("/tmp/mock_temp")
        mock_tempdir.return_value.__enter__.return_value = str(temp_path)

        # Mock successful subprocess run
        mock_result = Mock()
        mock_result.stdout = "Successfully received certificate"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock that fullchain file exists after certbot
        mock_exists.return_value = True

        # Mock certificate content to return
        cert_content = b"-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"

        wrapper = CertbotWrapper(staging=True)

        with patch("builtins.open", mock_open(read_data=cert_content)):
            with patch("os.chmod"):  # Mock file permission changes
                result = wrapper.obtain_certificate_with_csr(
                    email="test@example.com",
                    webroot_path="/tmp/webroot",
                    csr_pem=b"mock csr",
                    account_key_pem=b"mock account key",
                )

        assert result == cert_content
        mock_run.assert_called_once()

        # Verify certbot command structure
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert "certbot" in cmd
        assert "certonly" in cmd
        assert "--webroot" in cmd
        assert "--csr" in cmd
        assert "--agree-tos" in cmd
        assert "--non-interactive" in cmd
        assert "--fullchain-path" in cmd
        assert "test@example.com" in cmd
        assert kwargs["timeout"] == 300

    @patch("subprocess.run")
    @patch("tempfile.TemporaryDirectory")
    def test_obtain_certificate_with_csr_failure(self, mock_tempdir, mock_run):
        """Test certificate obtaining failure."""
        temp_path = Path("/tmp/mock_temp")
        mock_tempdir.return_value.__enter__.return_value = str(temp_path)

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "certbot", stderr="Rate limit exceeded"
        )

        wrapper = CertbotWrapper(staging=False)

        with patch("builtins.open", mock_open()):
            with patch("os.chmod"):
                with pytest.raises(Exception, match="Certbot failed"):
                    wrapper.obtain_certificate_with_csr(
                        email="test@example.com",
                        webroot_path="/tmp/webroot",
                        csr_pem=b"mock csr",
                        account_key_pem=b"mock account key",
                    )

    @patch("subprocess.run")
    @patch("tempfile.TemporaryDirectory")
    def test_obtain_certificate_with_csr_timeout(self, mock_tempdir, mock_run):
        """Test certificate obtaining timeout."""
        temp_path = Path("/tmp/mock_temp")
        mock_tempdir.return_value.__enter__.return_value = str(temp_path)

        mock_run.side_effect = subprocess.TimeoutExpired("certbot", 300)

        wrapper = CertbotWrapper(staging=False)

        with patch("builtins.open", mock_open()):
            with patch("os.chmod"):
                with pytest.raises(Exception, match="Certbot command timed out"):
                    wrapper.obtain_certificate_with_csr(
                        email="test@example.com",
                        webroot_path="/tmp/webroot",
                        csr_pem=b"mock csr",
                        account_key_pem=b"mock account key",
                    )

    @patch("subprocess.run")
    @patch("tempfile.TemporaryDirectory")
    @patch("os.path.exists")
    def test_obtain_certificate_with_csr_fullchain_not_found(
        self, mock_exists, mock_tempdir, mock_run
    ):
        """Test certificate obtaining when fullchain file is not found."""
        temp_path = Path("/tmp/mock_temp")
        mock_tempdir.return_value.__enter__.return_value = str(temp_path)

        # Mock successful subprocess run but fullchain file not found
        mock_result = Mock()
        mock_result.stdout = "Successfully received certificate"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        mock_exists.return_value = False  # Fullchain file not found

        wrapper = CertbotWrapper(staging=True)

        with patch("builtins.open", mock_open()):
            with patch("os.chmod"):
                with pytest.raises(Exception, match="Fullchain file not found"):
                    wrapper.obtain_certificate_with_csr(
                        email="test@example.com",
                        webroot_path="/tmp/webroot",
                        csr_pem=b"mock csr",
                        account_key_pem=b"mock account key",
                    )


# Integration Tests
class TestCertificateManagerIntegration:
    """Integration tests for certificate state transitions and complex scenarios."""

    @patch.object(CertificateManager, "is_cert_valid")
    @patch.object(CertificateManager, "create_or_renew_certificate")
    def test_manage_cert_creation_and_renewal_invalid_cert(
        self, mock_create_renew, mock_is_valid, temp_dir
    ):
        """Test certificate management when current cert is invalid."""
        mock_is_valid.return_value = False

        manager = create_cert_manager(temp_dir)

        # Mock the supervisor's setup_nginx_https_config method
        with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
            manager.manage_cert_creation_and_renewal()

            mock_create_renew.assert_called_once()
            mock_setup_nginx.assert_called_once()

    @patch.object(CertificateManager, "is_cert_valid")
    @patch.object(CertificateManager, "create_or_renew_certificate")
    @patch.object(Supervisor, "setup_nginx_https_config")
    def test_manage_cert_creation_and_renewal_valid_cert(
        self, mock_setup_nginx, mock_create_renew, mock_is_valid, temp_dir
    ):
        """Test certificate management when current cert is valid."""
        mock_is_valid.return_value = True

        manager = create_cert_manager(temp_dir)

        manager.manage_cert_creation_and_renewal()

        mock_create_renew.assert_not_called()
        mock_setup_nginx.assert_not_called()

    @patch.object(CertificateManager, "is_cert_valid")
    @patch.object(CertificateManager, "create_or_renew_certificate")
    def test_manage_cert_creation_and_renewal_cert_creation_fails(
        self, mock_create_renew, mock_is_valid, temp_dir
    ):
        """Test certificate management when cert creation fails."""
        mock_is_valid.return_value = False
        mock_create_renew.side_effect = Exception("Certificate creation failed")

        manager = create_cert_manager(temp_dir)

        # Should not raise exception, just log error
        manager.manage_cert_creation_and_renewal()

    def test_startup_init_dev_mode_with_valid_cert(
        self, temp_dir, mock_certificate, mock_private_key
    ):
        """Test startup initialization in dev mode with existing valid certificate."""
        manager = create_cert_manager(temp_dir, dev_mode=True)

        # Save a valid certificate
        manager.save_certificate_and_key(mock_certificate, mock_private_key)

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # In dev mode with valid cert: should emit event, setup nginx, and manage certs
                    mock_emit.assert_called_once()
                    mock_setup_nginx.assert_called_once()
                    mock_manage.assert_called_once()

    def test_startup_init_production_deletes_self_signed_cert(
        self, temp_dir, mock_certificate, mock_private_key
    ):
        """Test startup initialization in production mode deletes existing self-signed certificates."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        # Save a self-signed certificate
        manager.save_certificate_and_key(mock_certificate, mock_private_key)
        assert manager.is_cert_self_signed()
        assert (temp_dir / "cert.pem").exists()
        assert (temp_dir / "key.pem").exists()

        with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
            manager.startup_init()

            # Self-signed cert should be deleted in production mode
            assert not (temp_dir / "cert.pem").exists()
            assert not (temp_dir / "key.pem").exists()
            mock_manage.assert_called_once()

    def test_startup_init_production_deletes_staging_cert_when_disabled(
        self, temp_dir, mock_letsencrypt_staging_cert, mock_private_key
    ):
        """Test startup initialization in production mode deletes staging certs when staging is disabled."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        # Save a staging certificate
        manager.save_certificate_and_key(mock_letsencrypt_staging_cert, mock_private_key)
        assert manager.is_cert_letsencrypt_staging()
        assert (temp_dir / "cert.pem").exists()
        assert (temp_dir / "key.pem").exists()

        with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
            manager.startup_init()

            # Staging cert should be deleted when production mode has staging disabled
            assert not (temp_dir / "cert.pem").exists()
            assert not (temp_dir / "key.pem").exists()
            mock_manage.assert_called_once()

    def test_startup_init_production_keeps_staging_cert_when_enabled(
        self, temp_dir, mock_letsencrypt_staging_cert, mock_private_key
    ):
        """Test startup initialization in production mode keeps staging certs when staging is enabled."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=True)

        # Save a staging certificate
        manager.save_certificate_and_key(mock_letsencrypt_staging_cert, mock_private_key)
        assert manager.is_cert_letsencrypt_staging()

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # Staging cert should be kept when staging is enabled
                    assert (temp_dir / "cert.pem").exists()
                    assert (temp_dir / "key.pem").exists()
                    mock_emit.assert_called_once()
                    mock_setup_nginx.assert_called_once()
                    mock_manage.assert_called_once()

    def test_startup_init_production_keeps_prod_cert(
        self, temp_dir, mock_letsencrypt_prod_cert, mock_private_key
    ):
        """Test startup initialization in production mode keeps production certificates."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        # Save a production certificate
        manager.save_certificate_and_key(mock_letsencrypt_prod_cert, mock_private_key)

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # Production cert should be kept
                    assert (temp_dir / "cert.pem").exists()
                    assert (temp_dir / "key.pem").exists()
                    mock_emit.assert_called_once()
                    mock_setup_nginx.assert_called_once()
                    mock_manage.assert_called_once()

    def test_startup_init_no_existing_cert(self, temp_dir):
        """Test startup initialization when no existing certificate is present."""
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # No cert exists, so should not emit or setup nginx, but should manage certs
                    mock_emit.assert_not_called()
                    mock_setup_nginx.assert_not_called()
                    mock_manage.assert_called_once()

    @patch.object(CertificateManager, "generate_deterministic_key")
    @patch("cert_manager.cmgr.CertbotWrapper")
    def test_fullchain_integration_lets_encrypt_to_file(
        self,
        mock_certbot_class,
        mock_gen_key,
        temp_dir,
        mock_private_key,
    ):
        """Integration test: Let's Encrypt fullchain creation -> save -> validate -> read back."""
        # Setup mocks for Let's Encrypt with fullchain
        mock_gen_key.return_value = mock_private_key
        mock_certbot = Mock()

        # Create mock fullchain by combining real certificate structures with our test certificates
        leaf_cert = TestCertificateManager()._create_test_certificate(
            "example.com", "Intermediate Authority", mock_private_key
        )
        intermediate_cert = TestCertificateManager()._create_test_certificate(
            "Intermediate Authority", "Root Authority", mock_private_key
        )
        root_cert = TestCertificateManager()._create_test_certificate(
            "Root Authority", "Root Authority", mock_private_key
        )

        fullchain_pem = (
            leaf_cert.public_bytes(Encoding.PEM)
            + intermediate_cert.public_bytes(Encoding.PEM)
            + root_cert.public_bytes(Encoding.PEM)
        )

        mock_certbot.obtain_certificate_with_csr.return_value = fullchain_pem
        mock_certbot_class.return_value = mock_certbot

        # Create manager in production mode
        manager = create_cert_manager(temp_dir, dev_mode=False, letsencrypt_staging=False)

        # Step 1: Create Let's Encrypt certificate (should return fullchain)
        cert_chain = manager.create_lets_encrypt_cert(mock_private_key)
        assert len(cert_chain) == 3, "Should get fullchain with 3 certificates"

        # Step 2: Save the certificate chain
        manager.save_certificate_and_key(cert_chain, mock_private_key)

        # Step 3: Verify files exist
        cert_file = temp_dir / "cert.pem"
        key_file = temp_dir / "key.pem"
        assert cert_file.exists()
        assert key_file.exists()

        # Step 4: Read back and verify all certificates are present
        with open(cert_file, "rb") as f:
            saved_certs = x509.load_pem_x509_certificates(f.read())

        assert len(saved_certs) == 3, f"Should have saved 3 certificates, got {len(saved_certs)}"

        # Step 5: Verify certificate validation methods work with fullchain
        assert manager.is_cert_valid(), "Certificate should be valid"
        assert not manager.is_cert_self_signed(), "Should not be self-signed (has intermediate)"
        assert not manager.is_cert_letsencrypt_staging(), "Should not be staging"

        # Step 6: Verify certificate order and content match
        for i, (original, saved) in enumerate(zip(cert_chain, saved_certs)):
            assert original.subject == saved.subject, f"Certificate {i} subject mismatch"
            assert original.issuer == saved.issuer, f"Certificate {i} issuer mismatch"
            assert original.serial_number == saved.serial_number, f"Certificate {i} serial mismatch"

        # Step 7: Verify emit_new_cert_event works with fullchain
        with patch("cert_manager.cmgr.DstackClient") as mock_dstack_client:
            mock_client = Mock()
            mock_dstack_client.return_value = mock_client
            manager.emit_new_cert_event()  # Should not raise exception
            mock_dstack_client.assert_called_once()
            mock_client.emit_event.assert_called_once()

    @patch("schedule.every")
    @patch("time.sleep")
    def test_run_method_scheduling(self, mock_sleep, mock_schedule):
        """Test the main run method scheduling logic."""
        # Mock schedule object
        mock_day = Mock()
        mock_at = Mock()
        mock_do = Mock()
        mock_day.at.return_value = mock_at
        mock_at.do.return_value = mock_do
        mock_schedule.return_value.day = mock_day

        # Mock sleep to only run once
        mock_sleep.side_effect = [None, KeyboardInterrupt()]  # Exit after first iteration

        manager = create_cert_manager(Path("/tmp"))

        with patch.object(manager, "is_cert_self_signed", return_value=False):
            with patch.object(manager, "is_cert_letsencrypt_staging", return_value=False):
                with patch.object(manager, "is_cert_valid", return_value=True):
                    with patch.object(manager, "emit_new_cert_event"):
                        with patch.object(manager.supervisor, "setup_nginx_https_config"):
                            with patch.object(manager, "manage_cert_creation_and_renewal"):
                                with patch("schedule.run_pending"):
                                    try:
                                        manager.run()
                                    except KeyboardInterrupt:
                                        pass  # Expected to exit the loop

        # Verify scheduling was set up
        mock_schedule.assert_called()
        mock_day.at.assert_called_with("00:00")
        mock_at.do.assert_called_once()

    def test_force_delete_cert_files_production_letsencrypt_prod(
        self, temp_dir, mock_letsencrypt_prod_cert, mock_private_key
    ):
        """Test force delete removes production Let's Encrypt certificate even in production mode."""
        # Create manager in production mode with force delete enabled
        manager = CertificateManager(
            domain="test.example.com",
            dev_mode=False,
            cert_email="test@example.com",
            letsencrypt_staging=False,
            letsencrypt_account_version="v1",
            cert_path=temp_dir,
            acme_path=temp_dir / "acme",
            force_rm_cert_files=True,  # This is the key - force delete is enabled
        )

        # Save a production Let's Encrypt certificate
        manager.save_certificate_and_key(mock_letsencrypt_prod_cert, mock_private_key)

        # Verify files exist before force delete
        assert (temp_dir / "cert.pem").exists()
        assert (temp_dir / "key.pem").exists()

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # Files should be deleted despite being production Let's Encrypt certs in production mode
                    assert not (temp_dir / "cert.pem").exists()
                    assert not (temp_dir / "key.pem").exists()

                    # Should not emit event or setup nginx since cert was deleted
                    mock_emit.assert_not_called()
                    mock_setup_nginx.assert_not_called()
                    mock_manage.assert_called_once()

    def test_force_delete_cert_files_disabled_keeps_production_cert(
        self, temp_dir, mock_letsencrypt_prod_cert, mock_private_key
    ):
        """Test that production certs are kept when force delete is disabled (default behavior)."""
        # Create manager in production mode with force delete disabled (default)
        manager = CertificateManager(
            domain="test.example.com",
            dev_mode=False,
            cert_email="test@example.com",
            letsencrypt_staging=False,
            letsencrypt_account_version="v1",
            cert_path=temp_dir,
            acme_path=temp_dir / "acme",
            force_rm_cert_files=False,  # Explicitly disabled for clarity
        )

        # Save a production Let's Encrypt certificate
        manager.save_certificate_and_key(mock_letsencrypt_prod_cert, mock_private_key)

        # Verify files exist before startup
        assert (temp_dir / "cert.pem").exists()
        assert (temp_dir / "key.pem").exists()

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # Files should still exist (normal behavior - prod certs are kept)
                    assert (temp_dir / "cert.pem").exists()
                    assert (temp_dir / "key.pem").exists()

                    # Should emit event and setup nginx since cert exists and is valid
                    mock_emit.assert_called_once()
                    mock_setup_nginx.assert_called_once()
                    mock_manage.assert_called_once()

    def test_force_delete_cert_files_staging_cert_in_production(
        self, temp_dir, mock_letsencrypt_staging_cert, mock_private_key
    ):
        """Test force delete removes staging certificate in production mode (edge case coverage)."""
        # Create manager in production mode with force delete enabled
        manager = CertificateManager(
            domain="test.example.com",
            dev_mode=False,
            cert_email="test@example.com",
            letsencrypt_staging=False,  # Production mode, staging disabled
            letsencrypt_account_version="v1",
            cert_path=temp_dir,
            acme_path=temp_dir / "acme",
            force_rm_cert_files=True,
        )

        # Save a staging Let's Encrypt certificate
        manager.save_certificate_and_key(mock_letsencrypt_staging_cert, mock_private_key)

        # Verify files exist before force delete
        assert (temp_dir / "cert.pem").exists()
        assert (temp_dir / "key.pem").exists()

        with patch.object(manager, "emit_new_cert_event") as mock_emit:
            with patch.object(manager.supervisor, "setup_nginx_https_config") as mock_setup_nginx:
                with patch.object(manager, "manage_cert_creation_and_renewal") as mock_manage:
                    manager.startup_init()

                    # Files should be deleted by force delete (happens first, before staging check)
                    assert not (temp_dir / "cert.pem").exists()
                    assert not (temp_dir / "key.pem").exists()

                    # Should not emit event or setup nginx since cert was deleted
                    mock_emit.assert_not_called()
                    mock_setup_nginx.assert_not_called()
                    mock_manage.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
