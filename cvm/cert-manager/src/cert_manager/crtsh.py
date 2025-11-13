"""Module for interacting with crt.sh to query and download certificates."""

import json
from datetime import datetime, timezone
import urllib3
import logging


logger = logging.getLogger("cert-manager")


# crt.sh isn't that reliable, so we add retry logic to our HTTP requests
def new_retrying_http_pool() -> urllib3.PoolManager:
    """Create a urllib3 PoolManager with retry logic for crt.sh queries.
    Returns:
        urllib3.PoolManager: Configured HTTP pool manager
    """
    retry_strategy = urllib3.Retry(
        total=5,  # Total number of retries
        backoff_factor=2,  # Wait 2, 4, 8, 16, 32 seconds between retries
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
    )
    return urllib3.PoolManager(
        retries=retry_strategy,
        timeout=urllib3.Timeout(connect=10.0, read=30.0),
        headers={"User-Agent": "cert-manager"},
    )


def is_cert_revoked(cert_id: str) -> bool:
    """Check if a certificate is revoked using crt.sh API.

    Args:
        cert_id (str): The crt.sh ID of the certificate to check.
    Returns:
        bool: True if the certificate is revoked, False otherwise.
    """
    try:
        url = f"https://crt.sh/?id={cert_id}&output=csv"
        logger.info(f"Checking if certificate is revoked on crt.sh: id={cert_id}")

        http = new_retrying_http_pool()

        response = http.request("GET", url)

        if response.status != 200:
            logger.error(f"crt.sh returned status {response.status} for id {cert_id}")
            return False

        revoked = b"Revoked (cessationOfOperation)" in response.data
        if revoked:
            logger.info(f"Certificate id={cert_id} is revoked")
        else:
            logger.info(f"Certificate id={cert_id} is not revoked")

        return revoked

    except Exception as e:
        logger.error(f"Unexpected error checking certificate revocation on crt.sh: {e}")
        return False


def get_valid_certs_from_crtsh(domain: str, exclude_serial_numbers: list[int] = []) -> list:
    """Query crt.sh for valid (non-revoked, non-expired) certificates for the managed domain.

    Args:
        execlude_serial_numbers: List of serial numbers to exclude from the result list

    Returns:
        list: List of certificate IDs (as strings) that are currently valid.
    """
    try:
        http = new_retrying_http_pool()
        # Query crt.sh API for certificates
        url = f"https://crt.sh/?q={domain}&output=json&deduplicate=Y"
        logger.info(f"Querying crt.sh for valid certificates: {url}")

        response = http.request("GET", url)

        if response.status != 200:
            logger.error(f"crt.sh returned status {response.status}")
            return []

        data = json.loads(response.data.decode("utf-8"))

        if not data:
            logger.info(f"No certificates found for domain {domain} on crt.sh")
            return []

        # Filter for valid certificates (not expired, not revoked)
        valid_certs = []
        now = datetime.now(timezone.utc)

        for cert_entry in data:
            # Parse the not_after date
            try:
                not_after_str = cert_entry.get("not_after")
                cert_id = cert_entry.get("id")
                serial_number = cert_entry.get("serial_number")

                logger.debug(
                    f"Processing cert entry:\
                        id={cert_id}, serial_number={serial_number}, not_after={not_after_str}"
                )

                if not not_after_str:
                    logger.debug(f"Skipping cert id={cert_id} due to missing not_after date")
                    continue

                # crt.sh returns dates in ISO format like "2025-02-11T23:59:59"
                not_after = datetime.fromisoformat(not_after_str)
                # If the datetime is naive (no timezone), assume UTC
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)

                # Check if certificate is still valid (not expired)
                if not_after > now:
                    # formats can change (how many zeros are on the left) so we compare values
                    if int(serial_number, 16) in exclude_serial_numbers:
                        logger.debug(f"Excluding certificate with serial number: {serial_number}")
                        continue
                    if is_cert_revoked(cert_id):
                        logger.debug(f"Excluding revoked certificate with id: {cert_id}")
                        continue
                    if cert_id:
                        # Only include Let's Encrypt certificates
                        issuer_name = cert_entry.get("issuer_name", "")
                        if "Let's Encrypt" in issuer_name:
                            valid_certs.append(str(cert_id))
                            logger.debug(
                                f"Found valid Let's Encrypt cert: id={cert_id}, expires={not_after}"
                            )
                        else:
                            logger.debug(
                                f"Skipping non-Let's Encrypt cert: id={cert_id}, "
                                f"issuer={issuer_name}"
                            )

            except (ValueError, TypeError) as e:
                logger.debug(f"Error parsing certificate entry: {e}")
                continue

        logger.info(f"Found {len(valid_certs)} valid Let's Encrypt certificates for {domain}")
        return valid_certs

    except urllib3.exceptions.HTTPError as e:
        logger.warning(f"Failed to query crt.sh (HTTP error): {e}")
        return []
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse crt.sh response: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error querying crt.sh: {e}")
        return []


def download_cert_from_crtsh(cert_id: str) -> bytes:
    """Download a certificate from crt.sh by certificate ID.

    Args:
        cert_id (str): The crt.sh ID of the certificate to download.

    Returns:
        bytes: PEM-encoded certificate.

    Raises:
        Exception: If unable to download the certificate.
    """
    try:
        http = new_retrying_http_pool()
        # Use crt.sh certificate ID to download the cert in PEM format
        url = f"https://crt.sh/?d={cert_id}"
        logger.info(f"Downloading certificate from crt.sh: id={cert_id}")

        response = http.request("GET", url)

        if response.status != 200:
            raise Exception(f"crt.sh returned status {response.status} for id {cert_id}")

        cert_pem = response.data

        if not cert_pem or not cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise Exception(f"Invalid certificate data received for id {cert_id}")

        logger.info(f"Successfully downloaded certificate: id={cert_id}")
        return cert_pem

    except urllib3.exceptions.HTTPError as e:
        logger.error(f"Failed to download certificate from crt.sh (HTTP error): {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to download certificate from crt.sh: {e}")
        raise
