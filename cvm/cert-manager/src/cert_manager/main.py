import os
import sys
import logging
from cert_manager.cmgr import CertificateManager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("cert-manager")

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "fatal": logging.FATAL,
}

if __name__ == "__main__":
    dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"
    letsencrypt_staging = os.getenv("LETSENCRYPT_STAGING", "false").lower() == "true"
    if dev_mode or letsencrypt_staging:
        logger.setLevel(logging.DEBUG)
        logger.debug("Logging set to DEBUG level due to dev mode or staging")

    log_level = os.getenv("LOG_LEVEL", "").lower()
    if log_level in LOG_LEVELS.keys():
        logger.setLevel(LOG_LEVELS[log_level])
        logger.debug(f"Logging level set to {log_level.upper()} from LOG_LEVEL env variable")

    domain = os.getenv("DOMAIN", "localhost")
    cert_email = os.getenv("EMAIL", "certbot@concrete-security.com")
    letsencrypt_account_version = os.getenv("LETSENCRYPT_ACCOUNT_VERSION", "v1")

    force_rm_cert_files = os.getenv("FORCE_RM_CERT_FILES", "false").lower() == "true"

    manager = CertificateManager(
        domain=domain,
        dev_mode=dev_mode,
        cert_email=cert_email,
        letsencrypt_staging=letsencrypt_staging,
        letsencrypt_account_version=letsencrypt_account_version,
        force_rm_cert_files=force_rm_cert_files,
    )
    try:
        manager.run()
    except KeyboardInterrupt:
        logger.info("Certificate manager stopped")
    except Exception as e:
        logger.error(f"Certificate manager error: {e}")
        sys.exit(1)
