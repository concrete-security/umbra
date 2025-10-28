"""
Certificate Manager Service

Handles TLS certificate creation, renewal, and key management for the secure-chat CVM.
Supports multiple replicas by synchronizing them via an S3 bucket.
"""

import os
import sys
import time
import logging
import subprocess
import tempfile
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
import schedule
from dstack_sdk import DstackClient

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class Supervisor:
    """Supervisor manages both Nginx and this Cert Manager.
    This class is a helper for configuring Nginx (base/https) and restarting it via Supervisor.
    """

    SUPERVISOR_CONF_PATH = "/etc/supervisor/conf.d/supervisord.conf"
    NGINX_CONF_PATH = "/etc/nginx/conf.d/default.conf"
    NGINX_BASE_CONF_PATH = "./nginx_conf/base.conf"
    NGINX_HTTPS_CONF_PATH = "./nginx_conf/https.conf"

    def __init__(
        self,
        supervisor_conf_path: Optional[str] = None,
        nginx_conf_path: Optional[str] = None,
        nginx_base_conf_path: Optional[str] = None,
        nginx_https_conf_path: Optional[str] = None,
    ):
        self.supervisor_conf_path = (
            supervisor_conf_path if supervisor_conf_path else self.SUPERVISOR_CONF_PATH
        )
        self.nginx_conf_path = nginx_conf_path if nginx_conf_path else self.NGINX_CONF_PATH
        self.nginx_base_conf_path = (
            nginx_base_conf_path if nginx_base_conf_path else self.NGINX_BASE_CONF_PATH
        )
        self.nginx_https_conf_path = (
            nginx_https_conf_path if nginx_https_conf_path else self.NGINX_HTTPS_CONF_PATH
        )

    def restart_nginx(self):
        """
        Restart nginx via supervisorctl.

        Raises:
            Exception: If the restart command fails or times out.
        """

        cmd = ["supervisorctl", "-c", self.supervisor_conf_path, "restart", "nginx"]

        logger.info(f"Restarting nginx via supervisorctl: {' '.join(cmd)}")

        if not os.path.exists(self.supervisor_conf_path):
            raise Exception(
                f"Supervisor configuration file not found at {self.supervisor_conf_path}"
            )

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout for restart
            )

            logger.info("Nginx restart completed successfully")
            logger.debug(f"Supervisorctl stdout: {result.stdout}")

            if result.stderr:
                logger.debug(f"Supervisorctl stderr: {result.stderr}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Nginx restart failed with exit code {e.returncode}")
            logger.error(f"Supervisorctl stderr: {e.stderr}")
            logger.error(f"Supervisorctl stdout: {e.stdout}")
            raise Exception("Nginx restart failed (see logs for more info)")

        except subprocess.TimeoutExpired:
            logger.error("Nginx restart command timed out")
            raise Exception("Nginx restart command timed out")

        except Exception as e:
            logger.error(f"Unexpected error restarting nginx: {e}")
            raise

    def setup_nginx_base_config(self):
        """
        Set up nginx with the base configuration and restart nginx.

        This configures nginx with HTTP-only settings, typically used during
        initial setup or when HTTPS certificates are not yet available.

        Raises:
            Exception: If the configuration setup or restart fails.
        """
        logger.info("Setting up nginx with base configuration (no HTTPS)")

        try:
            if not os.path.exists(self.nginx_base_conf_path):
                raise Exception(
                    f"Base nginx configuration not found at {self.nginx_base_conf_path}"
                )

            with open(self.nginx_base_conf_path, "r") as src:
                base_config = src.read()

            with open(self.nginx_conf_path, "w") as dst:
                dst.write(base_config)

            logger.info(f"Base configuration written to {self.nginx_conf_path}")

        except Exception as e:
            logger.error(f"Failed to setup nginx base configuration: {e}")
            raise

        # Restart nginx to apply the new configuration
        try:
            self.restart_nginx()
        except Exception as e:
            logger.error(f"Failed to restart nginx: {e}")
            raise

    def setup_nginx_https_config(self):
        """
        Set up nginx with the base + HTTPS configuration and restart nginx.

        This configures nginx with both HTTP and HTTPS settings, typically used
        after SSL certificates have been obtained and are available.

        Raises:
            Exception: If the configuration setup or restart fails.
        """
        logger.info("Setting up nginx with base + HTTPS configuration")

        try:
            if not os.path.exists(self.nginx_base_conf_path):
                raise Exception(
                    f"Base nginx configuration not found at {self.nginx_base_conf_path}"
                )
            if not os.path.exists(self.nginx_https_conf_path):
                raise Exception(
                    f"HTTPS nginx configuration not found at {self.nginx_https_conf_path}"
                )

            # Read both configurations
            with open(self.nginx_base_conf_path, "r") as src:
                base_config = src.read()

            with open(self.nginx_https_conf_path, "r") as src:
                https_config = src.read()

            # Combine configurations (base + https)
            combined_config = base_config + "\n" + https_config

            # Write combined configuration to nginx conf directory
            with open(self.nginx_conf_path, "w") as dst:
                dst.write(combined_config)

            logger.info(f"Combined base + HTTPS configuration written to {self.nginx_conf_path}")

        except Exception as e:
            logger.error(f"Failed to setup nginx HTTPS configuration: {e}")
            raise

        # Restart nginx to apply the new configuration
        try:
            self.restart_nginx()
        except Exception as e:
            logger.error(f"Failed to restart nginx: {e}")
            raise


class CertbotWrapper:
    """Wrapper class for certbot operations"""

    def __init__(self, staging: bool = False):
        self.staging = staging
        self.server_url = (
            "https://acme-staging-v02.api.letsencrypt.org/directory"
            if staging
            else "https://acme-v02.api.letsencrypt.org/directory"
        )

    def obtain_certificate_with_csr(
        self, email: str, webroot_path: str, csr_pem: bytes, account_key_pem: bytes
    ) -> bytes:
        """
        Obtain certificate using certbot with a pre-generated CSR.

        Args:
            email (str): Email for Let's Encrypt account
            webroot_path (str): Path where ACME challenges will be served
            csr_pem (bytes): PEM-encoded Certificate Signing Request
            account_key_pem (bytes): PEM-encoded account key for Let's Encrypt

        Returns:
            bytes: Certificate chain in PEM format

        Raises:
            Exception: If certbot fails to obtain the certificate
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Save CSR to temporary file
            csr_file = temp_path / "csr.pem"
            with open(csr_file, "wb") as f:
                f.write(csr_pem)
            os.chmod(csr_file, 0o600)

            # Save account key to temporary file (for account management)
            account_key_file = temp_path / "account_key.pem"
            with open(account_key_file, "wb") as f:
                f.write(account_key_pem)
            os.chmod(account_key_file, 0o600)

            # Prepare certbot command using CSR
            cmd = [
                "certbot",
                "certonly",
                "--webroot",
                "--webroot-path",
                webroot_path,
                "--csr",
                str(csr_file),
                "--email",
                email,
                "--agree-tos",
                "--non-interactive",
                "--server",
                self.server_url,
                "--work-dir",
                str(temp_path / "work"),
            ]

            logger.info(f"Running certbot command with CSR: {' '.join(cmd)}")

            try:
                result = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                )

                logger.info("Certbot command completed successfully")
                logger.debug(f"Certbot stdout: {result.stdout}")

                # When using CSR, certbot outputs certificate files in the current directory
                # with names based on the CSR filename
                cert_files = list(temp_path.glob("*cert*.pem")) + list(
                    temp_path.glob("*fullchain*.pem")
                )

                logger.debug(f"Files in temp directory: {[f.name for f in temp_path.iterdir()]}")

                if len(cert_files) != 2:
                    logger.error("Certificate files not found after certbot execution")
                    raise Exception("Certificate files not found after certbot execution")

                # Find the certificate and chain files
                cert_pem = ""
                chain_pem = ""

                for cert_file in cert_files:
                    with open(cert_file, "r") as f:
                        content = f.read()
                        if "cert" in cert_file.name.lower():
                            cert_pem = content
                        elif "chain" in cert_file.name.lower():
                            chain_pem = content

                # Combine certificate and chain
                fullchain_pem = cert_pem + chain_pem if chain_pem else cert_pem

                return fullchain_pem.encode()

            except subprocess.CalledProcessError as e:
                logger.error(f"Certbot command failed with exit code {e.returncode}")
                logger.error(f"Certbot stderr: {e.stderr}")
                logger.error(f"Certbot stdout: {e.stdout}")
                raise Exception(f"Certbot failed: {e.stderr}")

            except subprocess.TimeoutExpired:
                logger.error("Certbot command timed out")
                raise Exception("Certbot command timed out")

            except Exception as e:
                logger.error(f"Unexpected error running certbot: {e}")
                raise


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
    ):
        self.domain = domain
        self.dev_mode = dev_mode
        self.cert_email = cert_email
        self.letsencrypt_staging = letsencrypt_staging
        # used to easily switch to another account
        self.letsencrypt_account_version = letsencrypt_account_version
        self.supervisor = Supervisor()

        self.cert_path = Path("/etc/nginx/ssl/")
        self.acme_path = Path("/acme-challenge/")

        # Ensure directories exist
        self.cert_path.mkdir(exist_ok=True)

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

    def create_lets_encrypt_cert(self, private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
        """Create Let's Encrypt certificate using certbot"""
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

        # Load certificate from PEM
        cert = x509.load_pem_x509_certificate(fullchain_pem)

        logger.info("Successfully obtained Let's Encrypt certificate using certbot")
        return cert

    def create_self_signed_cert(self, private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
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

        return cert

    def save_certificate_and_key(
        self, cert: x509.Certificate, private_key: ec.EllipticCurvePrivateKey
    ):
        """Save certificate and private key to files.

        Args:
            cert (x509.Certificate): Certificate to save.
            private_key (ec.EllipticCurvePrivateKey): Private key to save.
        """
        cert_pem = cert.public_bytes(Encoding.PEM)

        # Save certificate
        cert_file = self.cert_path / self.CERT_FILENAME
        with open(cert_file, "wb") as f:
            f.write(cert_pem)

        logger.info(f"Certificate saved to {cert_file}")

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
                cert = x509.load_pem_x509_certificate(f.read())

            # Check if certificate expires within the defined threshold
            expiry_threshold = datetime.now(timezone.utc) + timedelta(
                days=self.CERT_EXPIRY_THRESHOLD_DAYS
            )
            if cert.not_valid_after_utc < expiry_threshold:
                logger.info(f"Certificate expires on {cert.not_valid_after_utc}, renewal needed")
                return False

            logger.info(f"Certificate valid until {cert.not_valid_after_utc}")
            return True

        # TODO: better error mgmt. Not all errors should lead to renewal
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")
            return False

    def create_or_renew_certificate(self):
        """Create or renew TLS certificate"""

        logger.info("Starting certificate creation/renewal process")

        if self.dev_mode:  # Development mode: create self-signed certificate
            private_key = self.generate_deterministic_key(f"cert/debug/{self.domain}/v1")
            cert = self.create_self_signed_cert(private_key)
            self.save_certificate_and_key(cert, private_key)
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
                    cert = self.create_lets_encrypt_cert(private_key)
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

            self.save_certificate_and_key(cert, private_key)

        # Emit new cert event to Dstack (extend RTMR3)
        cert_pem = cert.public_bytes(Encoding.PEM)
        cert_hash = sha256(cert_pem).hexdigest()
        if self.dev_mode:  # only log cert hash
            logger.info(f"New TLS Certificate: {cert_hash}")
        else:
            dstack_client = DstackClient()
            dstack_client.emit_event("New TLS Certificate", cert_hash)
            logger.info("Emitted new TLS certificate event to Dstack")

        logger.info("Certificate management completed successfully")

    def manage_cert_creation_and_renewal(self):
        """Manage certificate creation and renewal process.

        Checks if the certificate is valid, and creates or renews it if necessary.
        This will also setup Nginx with HTTPS, and restart it (load new cert/key).
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

    def run(self):
        """Main run loop"""

        # If cert is valid on startup, setup Nginx with HTTPS
        try:
            if self.is_cert_valid():
                self.supervisor.setup_nginx_https_config()
        except Exception as e:
            logger.error(f"Failed to setup and restart Nginx: {e}")

        # Initial certificate creation/check
        try:
            self.manage_cert_creation_and_renewal()
        except Exception as e:
            logger.error(f"Initial certificate management failed: {e}")

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


if __name__ == "__main__":
    dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"
    letsencrypt_staging = os.getenv("LETSENCRYPT_STAGING", "false").lower() == "true"
    if dev_mode or letsencrypt_staging:
        logger.setLevel(logging.DEBUG)
        logger.debug("Logging set to DEBUG level due to dev mode or staging")

    domain = os.getenv("DOMAIN", "localhost")
    cert_email = os.getenv("EMAIL", "certbot@concrete-security.com")
    letsencrypt_account_version = os.getenv("LETSENCRYPT_ACCOUNT_VERSION", "v1")

    manager = CertificateManager(
        domain=domain,
        dev_mode=dev_mode,
        cert_email=cert_email,
        letsencrypt_staging=letsencrypt_staging,
        letsencrypt_account_version=letsencrypt_account_version,
    )
    try:
        manager.run()
    except KeyboardInterrupt:
        logger.info("Certificate manager stopped")
    except Exception as e:
        logger.error(f"Certificate manager error: {e}")
        sys.exit(1)
