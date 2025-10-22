"""
CVM Test Suite.

This script tests all CVM components through the nginx proxy (just like end-users would).
"""

try:
    import argparse
    import json
    import ssl
    import sys
    import time
    import urllib3
    from urllib.parse import urlparse
    from urllib3.util.retry import Retry
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.x509.oid import ExtensionOID

    import requests
    from requests.adapters import HTTPAdapter

except ImportError:
    print("⚠️  You should install requirements_test.txt")
    print("")
    raise


class CVMTester:
    """Main test class for CVM services"""

    def __init__(
        self,
        base_url: str = "https://localhost",
        http_url: str = "http://localhost",
        dev_mode: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.http_url = http_url.rstrip("/")
        self.dev_mode = dev_mode
        self.verify_ssl = not dev_mode  # In production mode, verify SSL certificates
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with proper SSL configuration"""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.dev_mode:
            # In dev mode, disable SSL warnings for self-signed certificates
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return session

    def _print_test_header(self, test_name: str):
        """Print test header"""
        print("")
        print("-" * (len(test_name) + 4))
        print(f"🧪 {test_name}")
        print("-" * (len(test_name) + 4))

    def _print_success(self, message: str):
        """Print success message"""
        print(f"✅ {message}")

    def _print_error(self, message: str):
        """Print error message"""
        print(f"❌ {message}")

    def _print_warning(self, message: str):
        """Print warning message"""
        print(f"⚠️  {message}")

    def _print_info(self, message: str):
        """Print info message"""
        print(f"ℹ️  {message}")

    def wait_for_vllm(self, timeout: int = 300) -> bool:
        """Wait for the vLLM service to become ready"""
        self._print_test_header("Waiting for vLLM service to become ready")

        start_time = time.time()
        attempt = 0

        while time.time() - start_time < timeout:
            attempt += 1
            try:
                response = self.session.get(
                    f"{self.base_url}/v1/models", verify=self.verify_ssl, timeout=3
                )
                if response.status_code == 200:
                    self._print_success(f"vLLM service is ready! (attempt {attempt})")
                    return True
            except requests.exceptions.SSLError as e:
                print(f"SSL error occurred: {e}")
                return False
            except requests.exceptions.RequestException as e:
                self._print_warning(f"request exception: {type(e)} {e}")
                pass

            if attempt % 12 == 0:  # Print every minute
                elapsed = int(time.time() - start_time)
                print(
                    f"Attempt {attempt}: vLLM service not ready yet, waiting... ({elapsed}s elapsed)"
                )

            time.sleep(5)

        self._print_error(f"vLLM service failed to start after {timeout} seconds")
        return False

    def wait_for_nginx(self, timeout: int = 300) -> bool:
        """Wait for the nginx proxy to become ready"""
        self._print_test_header("Waiting for nginx proxy to become ready")

        start_time = time.time()
        attempt = 0

        while time.time() - start_time < timeout:
            attempt += 1
            try:
                response = self.session.get(
                    f"{self.base_url}/health", verify=self.verify_ssl, timeout=3
                )
                if response.status_code == 200:
                    self._print_success(f"Nginx proxy is ready! (attempt {attempt})")
                    return True
            except requests.exceptions.SSLError as e:
                print(f"SSL error occurred: {e}")
                return False
            except requests.exceptions.RequestException as e:
                self._print_warning(f"request exception: {type(e)} {e}")
                pass

            if attempt % 12 == 0:  # Print every minute
                elapsed = int(time.time() - start_time)
                print(
                    f"Attempt {attempt}: Nginx proxy not ready yet, waiting... ({elapsed}s elapsed)"
                )

            time.sleep(5)

        self._print_error(f"Nginx proxy failed to start after {timeout} seconds")
        return False

    def test_certificate(self) -> bool:
        """Test certificate validation based on dev/prod mode"""
        mode = "Development" if self.dev_mode else "Production"
        self._print_test_header(f"Testing SSL Certificate ({mode} Mode)")

        try:
            # Parse URL to get hostname and port
            parsed = urlparse(self.base_url)
            hostname = parsed.hostname or "localhost"
            port = parsed.port or 443

            # Get certificate
            cert_pem = ssl.get_server_certificate((hostname, port))
            cert = load_pem_x509_certificate(cert_pem.encode())

            # Extract subject and issuer information
            subject = cert.subject
            issuer = cert.issuer

            # Get common name from subject
            common_name = None
            for attribute in subject:
                if attribute.oid._name == "commonName":
                    common_name = attribute.value
                    break

            # Check Subject Alternative Names
            san_names = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san_ext.value:
                    san_names.append(name.value)
            except Exception as e:
                self._print_info(f"Could not parse Subject Alternative Names: {e}")

            localhost_valid = (
                common_name in ["localhost", "127.0.0.1"]
                or "localhost" in san_names
                or "127.0.0.1" in san_names
            )

            if localhost_valid:
                if self.dev_mode:
                    self._print_success(
                        f"Certificate is valid for localhost (CN: {common_name}, SAN: {san_names})"
                    )
                else:
                    self._print_error(
                        f"Certificate is valid for localhost while in production mode"
                    )
                    return False
            else:
                if self.dev_mode:
                    self._print_warning(
                        f"Certificate is not valid for localhost (CN: {common_name}, SAN: {san_names})"
                    )

            # Check if it's self-signed by comparing issuer and subject
            is_self_signed = subject == issuer

            if self.dev_mode:
                # In dev mode, expect self-signed certificates
                if is_self_signed:
                    self._print_success(
                        "Certificate is self-signed (as expected in dev mode)"
                    )
                else:
                    issuer_cn = None
                    for attribute in issuer:
                        if attribute.oid._name == "commonName":
                            issuer_cn = attribute.value
                            break
                    self._print_warning(
                        f"Certificate is not self-signed in dev mode (signed by: {issuer_cn or 'Unknown'})"
                    )
            else:
                # In production mode, expect certificates from trusted CA (trusted: should be checked during HTTPS requests)
                if is_self_signed:
                    self._print_error(
                        "Certificate is self-signed in production mode (should be from trusted CA)"
                    )
                    return False
                else:
                    issuer_cn = None
                    for attribute in issuer:
                        if attribute.oid._name == "commonName":
                            issuer_cn = attribute.value
                            break
                    self._print_success(
                        f"Certificate is signed by trusted CA: {issuer_cn or 'Unknown'}"
                    )

            # Print certificate details
            self._print_info(
                f"Certificate valid from: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}"
            )

            return True

        except Exception as e:
            self._print_error(f"Certificate test failed: {str(e)}")
            return False

    def test_http_redirect(self) -> bool:
        """Test HTTP to HTTPS redirect"""
        self._print_test_header("Testing HTTP to HTTPS Redirect")

        try:
            # Test redirect without following it
            response = self.session.get(
                f"{self.http_url}/health", allow_redirects=False, timeout=3
            )

            if response.status_code == 301:
                location = response.headers.get("location", "")
                if location.startswith("https://"):
                    self._print_success(f"HTTP redirects to HTTPS: {location}")
                    return True
                else:
                    self._print_error(f"HTTP redirects but not to HTTPS: {location}")
                    return False
            else:
                self._print_error(f"Expected 301 redirect, got {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            self._print_error(f"HTTP redirect test failed: {str(e)}")
            return False

    def test_health(self) -> bool:
        """Test health endpoint"""
        self._print_test_header("Testing Health Endpoint")

        try:
            response = self.session.get(
                f"{self.base_url}/health", verify=self.verify_ssl, timeout=3
            )

            if response.status_code == 200:
                self._print_success("Health endpoint working via HTTPS")
                return True
            else:
                self._print_error(
                    f"Health endpoint failed with status {response.status_code}"
                )
                return False

        except requests.exceptions.RequestException as e:
            self._print_error(f"Health endpoint test failed: {str(e)}")
            return False

    def test_attestation(self) -> bool:
        """Test attestation service endpoints"""
        mode = "Development" if self.dev_mode else "Production"
        self._print_test_header(f"Testing Attestation Service Endpoints ({mode} Mode)")

        try:
            # Test TDX quote endpoint
            payload = {"report_data": "testdata"}

            response = self.session.post(
                f"{self.base_url}/tdx_quote",
                json=payload,
                verify=self.verify_ssl,
                timeout=3,
            )

            if response.status_code == 200:
                self._print_success("TDX quote endpoint working via HTTPS")
                try:
                    data = response.json()
                    if "quote" in data:
                        self._print_info(
                            f"Received quote with length: {len(data['quote'])}"
                        )
                except json.JSONDecodeError:
                    self._print_info("Response received but not JSON")
                return True
            elif response.status_code == 500:
                if self.dev_mode:
                    # In dev mode, 500 errors are acceptable (mock environment)
                    self._print_warning(
                        "TDX quote endpoint may require TDX environment (acceptable in dev mode)"
                    )
                    self._print_info(f"Response status: {response.status_code}")
                    return True
                else:
                    # In production mode, 500 errors are failures
                    self._print_error(
                        f"TDX quote endpoint failed with status 500 (not acceptable in production)"
                    )
                    return False
            else:
                self._print_error(
                    f"TDX quote endpoint failed with status {response.status_code}"
                )
                return False

        except requests.exceptions.RequestException as e:
            self._print_error(f"Attestation test failed: {str(e)}")
            return False

    def test_vllm(self) -> bool:
        """Test vLLM/mock vLLM endpoints"""
        self._print_test_header("Testing vLLM/Mock vLLM Endpoints")

        success = True

        # Test models endpoint
        try:
            response = self.session.get(
                f"{self.base_url}/v1/models", verify=self.verify_ssl, timeout=3
            )

            if response.status_code == 200:
                self._print_success("vLLM models endpoint working via HTTPS")
                try:
                    data = response.json()
                    models = data.get("data", [])
                    self._print_info(f"Available models: {len(models)}")
                    for model in models[:3]:  # Show first 3 models
                        self._print_info(f"  - {model.get('id', 'Unknown')}")
                except json.JSONDecodeError:
                    self._print_warning("Models response not in expected JSON format")
            else:
                self._print_error(
                    f"vLLM models endpoint failed with status {response.status_code}"
                )
                success = False

        except requests.exceptions.RequestException as e:
            self._print_error(f"vLLM models test failed: {str(e)}")
            success = False

        # Test chat completions endpoint
        try:
            payload = {
                "model": "openai/gpt-oss-120b",
                "messages": [{"role": "user", "content": "Hello via HTTPS proxy!"}],
                "max_tokens": 50,
            }

            response = self.session.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                verify=self.verify_ssl,
                timeout=30,  # Longer timeout for AI responses
            )

            if response.status_code == 200:
                self._print_success("vLLM chat completions endpoint working via HTTPS")
                try:
                    data = response.json()
                    choices = data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        self._print_info(f"Response preview: {content[:100]}...")
                except json.JSONDecodeError:
                    self._print_warning("Chat response not in expected JSON format")
            else:
                self._print_error(
                    f"vLLM chat completions endpoint failed with status {response.status_code}"
                )
                success = False

        except requests.exceptions.RequestException as e:
            self._print_error(f"vLLM chat completions test failed: {str(e)}")
            success = False

        return success

    def run_all_tests(self) -> bool:
        """Run all test suites"""
        mode = "Development" if self.dev_mode else "Production"
        print("")
        print("")
        print(f"🚀 CVM Test Suite - Starting full tests ({mode} Mode)")
        print("=" * 60)

        results = {
            "certificate": self.test_certificate(),
            "redirect": self.test_http_redirect(),
            "health": self.test_health(),
            "attestation": self.test_attestation(),
            "vllm": self.test_vllm(),
        }

        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)

        passed = 0
        total = len(results)

        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name.upper():12} {status}")
            if result:
                passed += 1

        print(f"\nTotal: {passed}/{total} tests passed")

        if passed == total:
            print("🎉 All tests passed!")
            return True
        else:
            print("⚠️  Some tests failed or had warnings")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="CVM Test Suite - Test all CVM components via nginx proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    # Run all tests
  %(prog)s --health                 # Test only health endpoint
  %(prog)s --certificate            # Test only certificate validation
  %(prog)s --attestation --vllm     # Test attestation and vLLM endpoints
  %(prog)s --wait                   # Wait for services to be ready
  %(prog)s --base-url https://myhost:8443  # Use custom base URL
        """,
    )

    parser.add_argument(
        "--base-url",
        default="https://localhost",
        help="Base HTTPS URL for testing (default: https://localhost)",
    )
    parser.add_argument(
        "--http-url",
        default="http://localhost",
        help="Base HTTP URL for redirect testing (default: http://localhost)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Service wait timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Run in development mode (accept self-signed certs and 500 errors for quotes)",
    )

    # Test selection
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all tests (default if no specific tests selected)",
    )
    parser.add_argument(
        "--wait", action="store_true", help="Wait for services to be ready"
    )
    parser.add_argument(
        "--certificate", action="store_true", help="Test SSL certificate validation"
    )
    parser.add_argument(
        "--redirect", action="store_true", help="Test HTTP to HTTPS redirect"
    )
    parser.add_argument("--health", action="store_true", help="Test health endpoint")
    parser.add_argument(
        "--attestation", action="store_true", help="Test attestation service endpoints"
    )
    parser.add_argument(
        "--vllm", action="store_true", help="Test vLLM/mock vLLM endpoints"
    )

    args = parser.parse_args()

    # If no specific tests selected, run all
    if not any(
        [
            args.wait,
            args.certificate,
            args.redirect,
            args.health,
            args.attestation,
            args.vllm,
        ]
    ):
        args.all = True

    tester = CVMTester(args.base_url, args.http_url, args.dev)

    # Wait for services if requested or if running all tests
    if args.wait or args.all:
        if not tester.wait_for_nginx(args.timeout):
            sys.exit(1)

    if args.wait or args.all:
        if not tester.wait_for_vllm(args.timeout):
            sys.exit(1)

    # Run selected tests
    if args.all:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)

    # Run individual tests
    success = True

    if args.certificate:
        success &= tester.test_certificate()

    if args.redirect:
        success &= tester.test_http_redirect()

    if args.health:
        success &= tester.test_health()

    if args.attestation:
        success &= tester.test_attestation()

    if args.vllm:
        success &= tester.test_vllm()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
