import hashlib
import logging
import os
import re
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("auth-service")

# The application works by hashing tokens with a salt. The salt is randomly
# generated at startup and is not persisted, so tokens are only valid for
# the lifetime of the process.
AUTH_SALT = secrets.token_bytes(32)


def hash_token(token: str) -> bytes:
    """Hash a token with the application salt using SHA-256."""
    return hashlib.sha256(AUTH_SALT + token.encode()).digest()


# Minimum length for AUTH_SERVICE_TOKEN to be considered valid (Default: 32)
MIN_AUTH_SERVICE_TOKEN_LEN = os.environ.get("MIN_AUTH_SERVICE_TOKEN_LEN")
if MIN_AUTH_SERVICE_TOKEN_LEN is None:
    MIN_AUTH_SERVICE_TOKEN_LEN = 32
else:
    MIN_AUTH_SERVICE_TOKEN_LEN = int(MIN_AUTH_SERVICE_TOKEN_LEN)
AUTH_SERVICE_TOKEN_LEN = len(os.environ.get("AUTH_SERVICE_TOKEN", ""))
AUTH_SERVICE_TOKEN_HASH = (
    hash_token(os.environ.get("AUTH_SERVICE_TOKEN"))
    if AUTH_SERVICE_TOKEN_LEN >= MIN_AUTH_SERVICE_TOKEN_LEN
    else None
)


def token_match(token: str, expected_hash: bytes) -> bool:
    """Hash token and compare to expected hash in constant time."""
    provided_hash = hash_token(token)
    return secrets.compare_digest(provided_hash, expected_hash)


class AuthHandler(BaseHTTPRequestHandler):
    # Maximum allowed header size (8KB) and request line size (8KB)
    MAX_REQUEST_LINE = 8192
    MAX_HEADERS = 8192

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)

    def parse_request(self):
        """Override to enforce request size limits."""
        if not super().parse_request():
            return False

        # Check request line length
        if len(self.raw_requestline) > self.MAX_REQUEST_LINE:
            self.send_error(414, "Request-URI Too Long")
            return False

        # Check total headers size
        headers_size = sum(len(k) + len(v) for k, v in self.headers.items())
        if headers_size > self.MAX_HEADERS:
            self.send_error(431, "Request Header Fields Too Large")
            return False

        return True

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"healthy")
            return

        if self.path == "/auth":
            auth_header = self.headers.get("Authorization", "")

            if not AUTH_SERVICE_TOKEN_HASH:
                logger.error("AUTH_SERVICE_TOKEN environment variable not set")
                self.send_response(500)
                self.end_headers()
                return

            match = re.match(r"^Bearer\s+(.+)", auth_header)
            token = match.group(1) if match else ""
            if token_match(token, AUTH_SERVICE_TOKEN_HASH):
                logger.debug("Authentication successful")
                self.send_response(200)
                self.end_headers()
            else:
                logger.warning("Authentication failed: invalid or missing token")
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


def main():
    if MIN_AUTH_SERVICE_TOKEN_LEN < 32:
        logger.warning("MIN_AUTH_SERVICE_TOKEN_LEN is set below 32 - this is not recommended")
    if not AUTH_SERVICE_TOKEN_HASH:
        logger.warning(
            "AUTH_SERVICE_TOKEN environment not set or too short (min is "
            f"{MIN_AUTH_SERVICE_TOKEN_LEN}) - all auth requests will fail"
        )
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8081"))
    server = HTTPServer((host, port), AuthHandler)
    logger.info(f"Auth service listening on {host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down auth service")
        server.shutdown()


if __name__ == "__main__":
    main()
