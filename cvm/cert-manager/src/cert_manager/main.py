import os
import sys
import logging
from cert_manager.cmgr import CertificateManager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("cert-manager")


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
