"""
CertbotWrapper class

Wraps the certbot cli to obtain Let's Encrypt certificates from Python.
"""

import os
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("cert-manager")


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
            fullchain_path = temp_path / "fullchain.pem"
            cert_path = temp_path / "cert.pem"
            chain_path = temp_path / "chain.pem"
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
                "--cert-path",
                str(cert_path),
                "--chain-path",
                str(chain_path),
                "--fullchain-path",
                str(fullchain_path),
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

                if not os.path.exists(fullchain_path):
                    logger.error(f"Fullchain file not found at expected path: {fullchain_path}")
                    raise Exception("Fullchain file not found (see logs for more info)")

                with open(fullchain_path, "rb") as f:
                    fullchain_pem = f.read()

                return fullchain_pem

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
