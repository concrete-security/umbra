"""
Certificate Manager Service

Handles TLS certificate creation, renewal, and key management.
Supports multiple replicas by synchronizing them via an S3 bucket.
"""

import os
import time
import logging
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from typing import List, Union
import schedule
from dstack_sdk import DstackClient

from cert_manager.supervisor import Supervisor
from cert_manager.certbot import CertbotWrapper
from cert_manager import crtsh

logger = logging.getLogger("cert-manager")


class CertificateManager:
    CERT_FILENAME = "cert.pem"
    KEY_FILENAME = "key.pem"
    CERT_EXPIRY_THRESHOLD_DAYS = 30  # Days before expiry to renew

    def __init__(
        self,
        domain: str,
        dev_mode: bool,
        cert_email: str,
        letsencrypt_staging: bool,
        letsencrypt_account_version: str,
        cert_path: str = "/etc/nginx/ssl",
        acme_path: str = "/acme-challenge/",
        force_rm_cert_files: bool = False,
    ):
        self.domain = domain
        self.dev_mode = dev_mode
        self.cert_email = cert_email
        self.letsencrypt_staging = letsencrypt_staging
        # used to easily switch to another account
        self.letsencrypt_account_version = letsencrypt_account_version
        self.supervisor = Supervisor()

        self.cert_path = Path(cert_path)
        self.acme_path = Path(acme_path)

        # Ensure directories exist
        self.cert_path.mkdir(exist_ok=True)

        self.force_rm_cert_files = force_rm_cert_files

        logger.info(f"Domain: {self.domain}, Dev mode: {self.dev_mode}")

    def get_deterministic_key_material(self, key_path: str) -> bytes:
        """Get deterministic key material using Phala dstack SDK.

        Same compose hash + path will always yield the same key.

        Args:
            key_path (str): Used as an identifier of the key.
        Returns:
            bytes: Deterministic key material (32 bytes).
        Raises:
            Exception: If unable to retrieve key material.
        """
        try:
            if self.dev_mode:
                logger.warning(
                    "Dev mode active: using fixed key material. Don't do this for production!"
                )
                return b"\x01" * 32

            # Initialize dstack client
            dstack_client = DstackClient()
            logger.info("dstack SDK initialized successfully")
            # Use dstack SDK to get deterministic 32-byte key material
            result = dstack_client.get_key(f"{key_path}")
            key_material = result.decode_key()  # 32 bytes from dstack
            logger.info(f"Retrieved deterministic key material from dstack for path: {key_path}")
            return key_material

        except Exception as e:
            logger.error(f"Failed to get deterministic key material from dstack: {e}")
            raise

    def derive_ec_privatekey_from_key_material(
        self, key_material: bytes
    ) -> ec.EllipticCurvePrivateKey:
        """Derive EC private key from deterministic key material.

        Args:
            key_material (bytes): 32 bytes of key material.
        Returns:
            ec.EllipticCurvePrivateKey: Derived EC private key.
        """

        # TODO: check if this can lead to any problems
        return ec.derive_private_key(int.from_bytes(key_material, "big"), ec.SECP256R1())

    def revoke_other_valid_certificates(self):
        """Revoke all valid certificates for the domain, except current one.

        This queries crt.sh for valid certificates and revokes them using certbot.
        It doesn't revoke the currently used certificate.

        Only applies to production Let's Encrypt certificates.
        """
        logger.info(f"Checking for valid certificates to revoke for domain: {self.domain}")

        # Get current certificate serial number to exclude it from revocation
        current_cert_serial_number = None
        cert_file = self.cert_path / self.CERT_FILENAME
        if cert_file.exists():
            try:
                with open(cert_file, "rb") as f:
                    certs = x509.load_pem_x509_certificates(f.read())
                    # Get serial number from the leaf certificate
                    leaf_cert: x509.Certificate = certs[0]  # should be first
                    current_cert_serial_number = leaf_cert.serial_number
                    logger.info(f"Current certificate serial number: {current_cert_serial_number}")
            except Exception as e:
                logger.warning(f"Failed to load current certificate serial number: {e}")
        # Exclude current certificate from revocation
        exclude_serial_numbers = [current_cert_serial_number] if current_cert_serial_number else []

        # Get list of valid certificates from crt.sh
        valid_cert_ids = crtsh.get_valid_certs_from_crtsh(
            self.domain, exclude_serial_numbers=exclude_serial_numbers
        )

        if not valid_cert_ids:
            logger.info("No valid certificates found to revoke")
            return

        logger.info(f"Found {len(valid_cert_ids)} valid certificates to revoke")

        # Initialize certbot wrapper
        assert not self.letsencrypt_staging
        certbot = CertbotWrapper(staging=False)

        revoked_count = 0
        failed_count = 0

        for cert_id in valid_cert_ids:
            try:
                # Download the certificate from crt.sh
                cert_pem = crtsh.download_cert_from_crtsh(cert_id)

                # Revoke the certificate using domain validation (ACME challenge)
                # This allows revoking certificates issued by different accounts
                logger.info(f"Revoking certificate using domain validation: id={cert_id}")
                certbot.revoke_certificate_by_domain(
                    domain=self.domain,
                    cert_pem=cert_pem,
                    email=self.cert_email,
                    webroot_path=str(self.acme_path),
                    reason="superseded",  # Using "superseded" as we're issuing a new cert
                )
                revoked_count += 1
                logger.info(f"Successfully revoked certificate: id={cert_id}")

            except Exception as e:
                # Continue with other certificates even if one fails
                failed_count += 1
                logger.error(f"Failed to revoke certificate id={cert_id}: {e}")

        logger.info(
            f"Certificate revocation completed: {revoked_count} revoked, {failed_count} failed"
        )

    def generate_deterministic_key(self, key_path: str) -> ec.EllipticCurvePrivateKey:
        """Generate deterministic EC key using Phala dstack SDK.

        Args:
            key_path (str): Used as an identifier of the key.
        Returns:
            ec.EllipticCurvePrivateKey: Deterministically generated EC private key.
        """
        # Get deterministic key material
        key_material = self.get_deterministic_key_material(key_path)

        # Derive EC key from the material
        return self.derive_ec_privatekey_from_key_material(key_material)

    def create_lets_encrypt_cert(
        self, private_key: ec.EllipticCurvePrivateKey
    ) -> List[x509.Certificate]:
        """Create Let's Encrypt certificate using certbot.

        In production mode (not staging), this will revoke all valid certificates
        from crt.sh before issuing a new one, ensuring only one valid certificate
        exists at a time.
        """
        logger.info("Creating Let's Encrypt certificate using certbot")

        # Generate account key
        # Uses deterministic key so that same instances have the same key (could fix CAA to this account)
        # Versions allow you to change accounts by setting a different env variable
        account_key = self.generate_deterministic_key(
            f"letsencrypt-account/{self.domain}/{self.letsencrypt_account_version}"
        )

        # Create Certificate Signing Request with our deterministic private key
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(self.domain),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Serialize CSR and account key to PEM format for certbot
        csr_pem = csr.public_bytes(Encoding.PEM)

        account_key_pem = account_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        # Initialize certbot wrapper
        certbot = CertbotWrapper(staging=self.letsencrypt_staging)

        if self.letsencrypt_staging:
            logger.info("Using Let's Encrypt staging environment")
        else:
            logger.info("Using Let's Encrypt production environment")

        # Use certbot to obtain certificate with our CSR
        fullchain_pem = certbot.obtain_certificate_with_csr(
            email=self.cert_email,
            webroot_path=str(self.acme_path),
            csr_pem=csr_pem,
            account_key_pem=account_key_pem,
        )

        # Load certificate chain from PEM (handles fullchain)
        certs = x509.load_pem_x509_certificates(fullchain_pem)

        logger.info(
            f"Successfully obtained Let's Encrypt certificate chain using certbot ({len(certs)} certificates)"
        )
        return certs

    def create_self_signed_cert(
        self, private_key: ec.EllipticCurvePrivateKey
    ) -> List[x509.Certificate]:
        """Create self-signed certificate for development."""

        logger.info("Creating self-signed certificate for development")

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Concrete Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(self.domain),
                        x509.DNSName(f"*.{self.domain}"),
                        x509.DNSName("localhost"),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        logger.info("Self-signed certificate created successfully")

        return [cert]

    def save_certificate_and_key(
        self,
        cert_chain: Union[x509.Certificate, List[x509.Certificate]],
        private_key: ec.EllipticCurvePrivateKey,
    ):
        """Save certificate chain and private key to files.

        Args:
            cert_chain (Union[x509.Certificate, List[x509.Certificate]]): Certificate or certificate chain to save (fullchain).
            private_key (ec.EllipticCurvePrivateKey): Private key to save.
        """
        # Handle both single certificate and certificate chain inputs for backward compatibility
        if isinstance(cert_chain, x509.Certificate):
            # Convert single certificate to list
            cert_chain = [cert_chain]

        # Combine all certificates in the chain into a single PEM file
        cert_pems = []
        for cert in cert_chain:
            cert_pems.append(cert.public_bytes(Encoding.PEM))

        # Save certificate chain (fullchain)
        cert_file = self.cert_path / self.CERT_FILENAME
        with open(cert_file, "wb") as f:
            for cert_pem in cert_pems:
                f.write(cert_pem)

        logger.info(f"Certificate chain saved to {cert_file} ({len(cert_chain)} certificates)")

        # Save private key
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        key_file = self.cert_path / self.KEY_FILENAME
        with open(key_file, "wb") as f:
            f.write(key_pem)

        # Set secure permissions
        os.chmod(key_file, 0o600)
        logger.info(f"Private key saved to {key_file}")

    def is_cert_valid(self) -> bool:
        """Check if current certificate is valid.

        Checks if the cert and key files exist and if the cert is not expiring soon.
        """
        cert_file = self.cert_path / self.CERT_FILENAME
        key_file = self.cert_path / self.KEY_FILENAME

        if not cert_file.exists() or not key_file.exists():
            logger.info("Certificate or key files not found")
            return False

        try:
            with open(cert_file, "rb") as f:
                certs = x509.load_pem_x509_certificates(f.read())

            if not certs:
                logger.info("No certificates found in certificate file")
                return False

            # Check the first certificate (leaf certificate) for expiry
            leaf_cert = certs[0]
            expiry_threshold = datetime.now(timezone.utc) + timedelta(
                days=self.CERT_EXPIRY_THRESHOLD_DAYS
            )
            if leaf_cert.not_valid_after_utc < expiry_threshold:
                logger.info(
                    f"Certificate expires on {leaf_cert.not_valid_after_utc}, renewal needed"
                )
                return False

            logger.info(f"Certificate valid until {leaf_cert.not_valid_after_utc}")
            return True

        # TODO: better error mgmt. Not all errors should lead to renewal
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")
            return False

    def is_cert_self_signed(self) -> bool:
        """Check if the current certificate is self-signed.

        Returns:
            bool: True if the certificate is self-signed, False otherwise or if cert doesn't exist.
        """
        cert_file = self.cert_path / self.CERT_FILENAME

        if not cert_file.exists():
            logger.debug("Certificate file not found")
            return False

        try:
            with open(cert_file, "rb") as f:
                certs = x509.load_pem_x509_certificates(f.read())

            if not certs:
                logger.debug("No certificates found in certificate file")
                return False

            # Check the first certificate (leaf certificate) for self-signing
            leaf_cert = certs[0]
            # A certificate is self-signed if the issuer and subject are the same
            is_self_signed = leaf_cert.issuer == leaf_cert.subject

            if is_self_signed:
                logger.info("Certificate is self-signed")
            else:
                logger.info("Certificate is not self-signed")

            return is_self_signed

        except Exception as e:
            logger.error(f"Error checking if certificate is self-signed: {e}")
            return False

    def is_cert_letsencrypt_staging(self) -> bool:
        """Check if the current certificate was issued by Let's Encrypt staging.

        Returns:
            bool: True if the certificate was issued by Let's Encrypt staging, False otherwise.
        """
        cert_file = self.cert_path / self.CERT_FILENAME

        if not cert_file.exists():
            logger.debug("Certificate file not found while checking for Let's Encrypt staging")
            return False

        try:
            with open(cert_file, "rb") as f:
                certs = x509.load_pem_x509_certificates(f.read())

            if not certs:
                logger.debug("No certificates found in certificate file")
                return False

            # Check the first certificate (leaf certificate) for Let's Encrypt staging
            leaf_cert = certs[0]
            # Let's Encrypt staging issuer contains "Fake LE" or "Staging" in the CN
            issuer_cn = None
            for attribute in leaf_cert.issuer:
                if attribute.oid == NameOID.COMMON_NAME:
                    issuer_cn = attribute.value
                    break

            if issuer_cn:
                is_staging = "staging" in str(issuer_cn).lower()
                if is_staging:
                    logger.info(f"Certificate is from Let's Encrypt staging (issuer: {issuer_cn})")
                else:
                    logger.info(
                        f"Certificate is not from Let's Encrypt staging (issuer: {issuer_cn})"
                    )
                return is_staging
            else:
                logger.debug("Could not determine certificate issuer CN")
                return False

        except Exception as e:
            logger.error(f"Error checking if certificate is from Let's Encrypt staging: {e}")
            return False

    def delete_certificate_files(self):
        """Delete existing certificate and key files."""
        cert_file = self.cert_path / self.CERT_FILENAME
        key_file = self.cert_path / self.KEY_FILENAME

        files_deleted = []

        if cert_file.exists():
            try:
                cert_file.unlink()
                files_deleted.append(str(cert_file))
                logger.info(f"Deleted certificate file: {cert_file}")
            except Exception as e:
                logger.error(f"Error deleting certificate file {cert_file}: {e}")

        if key_file.exists():
            try:
                key_file.unlink()
                files_deleted.append(str(key_file))
                logger.info(f"Deleted key file: {key_file}")
            except Exception as e:
                logger.error(f"Error deleting key file {key_file}: {e}")

        if files_deleted:
            logger.info(f"Successfully deleted certificate files: {', '.join(files_deleted)}")
        else:
            logger.debug("No certificate files found to delete")

    def emit_new_cert_event(self):
        """Emit new cert event in RTMR3.

        This will only log the cert hash in dev mode.
        """
        cert_file = self.cert_path / self.CERT_FILENAME
        with open(cert_file, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())

        if not certs:
            logger.error("No certificates found in certificate file for event emission")
            return

        # Use the first certificate (leaf certificate) for the event
        leaf_cert = certs[0]
        cert_pem = leaf_cert.public_bytes(Encoding.PEM)
        cert_hash = sha256(cert_pem).hexdigest()

        if self.dev_mode:  # only log cert hash
            logger.info(f"New TLS Certificate: {cert_hash}")
        else:  # Emit new cert event to Dstack (extend RTMR3)
            dstack_client = DstackClient()
            dstack_client.emit_event("New TLS Certificate", cert_hash)
            logger.info("Emitted new TLS certificate event to Dstack")

    def create_or_renew_certificate(self):
        """Create or renew TLS certificate"""

        logger.info("Starting certificate creation/renewal process")

        if self.dev_mode:  # Development mode: create self-signed certificate
            private_key = self.generate_deterministic_key(f"cert/debug/{self.domain}/v1")
            cert_chain = self.create_self_signed_cert(private_key)
            self.save_certificate_and_key(cert_chain, private_key)
        # TODO: sync using S3 bucket for multiple replicas (in production)
        # We should have a lock file, then only one will push its generated cert, Others
        # will download it.
        # For now, we assume single instance.
        # See https://aws.amazon.com/about-aws/whats-new/2024/08/amazon-s3-conditional-writes/
        else:  # Production mode: use Let's Encrypt
            # TODO: maybe add seed into the S3 bucket for more randomness and key rotation on every
            # cert renewal
            private_key = self.generate_deterministic_key(f"cert/letsencrypt/{self.domain}/v1")
            # Retry logic for certbot failures
            wait_time = 10
            max_tries = 3
            i = 0
            success = False
            while not success:
                try:
                    cert_chain = self.create_lets_encrypt_cert(private_key)
                    success = True
                except Exception as e:
                    logger.error(f"Failed to create Let's Encrypt certificate: {e}")
                    if i < max_tries:
                        logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        i += 1
                        wait_time *= 2
                    else:
                        logger.error("Max retries reached, giving up.")
                        raise

            self.save_certificate_and_key(cert_chain, private_key)

        self.emit_new_cert_event()

        logger.info("Certificate management completed successfully")

    def manage_cert_creation_and_renewal(self):
        """Manage certificate creation and renewal process.

        Checks if the certificate is valid, and creates or renews it if necessary.
        This will also setup Nginx with HTTPS, and restart it (load new cert/key).
        In production mode, it also revokes all valid certs except the one used.
        """
        if not self.is_cert_valid():
            try:
                self.create_or_renew_certificate()
            except Exception as e:
                logger.error(f"Failed to create or renew certificate: {e}")
                return
            try:
                self.supervisor.setup_nginx_https_config()
            except Exception as e:
                logger.error(f"Failed to setup and restart Nginx: {e}")

        # Check for valid certs to revoke in production mode
        if not self.letsencrypt_staging and not self.dev_mode:
            logger.info("Production mode: revoking all valid certificates except the one used")
            try:
                self.revoke_other_valid_certificates()
            except Exception as e:
                logger.warning(f"Certificate revocation failed: {e}")

    def startup_init(self):
        """Initialization tasks to run on startup."""

        # TODO: merge different logic that deletes certs into is_cert_valid
        # and also add a condition where the key must have been generated by the current version?

        # Force delete cert files
        try:
            if self.force_rm_cert_files:
                logger.info("Force removal of certificate files")
                self.delete_certificate_files()
        except Exception as e:
            logger.error(f"Failed to force delete certificate files: {e}")

        # If in production (or staging), delete any existing self-signed certificate
        try:
            if not self.dev_mode and self.is_cert_self_signed():
                logger.info("Found self-signed certificate in production mode, deleting it")
                self.delete_certificate_files()
        except Exception as e:
            logger.error(f"Failed to check/delete self-signed certificate: {e}")

        # If in production, delete Let's Encrypt staging certificates
        try:
            if (
                not self.dev_mode
                and not self.letsencrypt_staging
                and self.is_cert_letsencrypt_staging()
            ):
                logger.info(
                    "Found Let's Encrypt staging certificate in production mode with staging disabled, deleting it"
                )
                self.delete_certificate_files()
        except Exception as e:
            logger.error(f"Failed to check/delete Let's Encrypt staging certificate: {e}")

        # If cert is valid on startup:
        # - emit new cert event in RTMR3
        # - setup Nginx with HTTPS
        try:
            if self.is_cert_valid():
                self.emit_new_cert_event()
                self.supervisor.setup_nginx_https_config()
        except Exception as e:
            logger.error(f"Failed to setup and restart Nginx: {e}")

        # Initial certificate creation/check
        try:
            self.manage_cert_creation_and_renewal()
        except Exception as e:
            logger.error(f"Initial certificate management failed: {e}")

    def run(self):
        """Main run loop"""

        # Should clean the current certs if needed (depends on current state and cmgr config)
        self.startup_init()

        # Schedule periodic cert management (everyday at midnight)
        try:
            schedule.every().day.at("00:00").do(self.manage_cert_creation_and_renewal)
        except Exception as e:
            logger.error(f"Failed to schedule certificate management routine: {e}")

        # Main loop
        logger.info("Certificate manager running, checking for renewal every day")
        while True:
            try:
                schedule.run_pending()
            except Exception as e:
                logger.error(f"Failed while running scheduled tasks: {e}")

            time.sleep(3600 * 6)  # Check every 6 hours
