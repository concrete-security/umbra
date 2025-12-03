"""
Test script for the attestation service endpoints
"""

import argparse

import requests


def test_health_endpoint(base_url, **kwargs):
    """Test the health endpoint"""
    try:
        response = requests.get(f"{base_url}/health")
        print(f"Health check: {response.status_code} - {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


def test_tdx_quote_post(base_url, no_tdx=False):
    """Test TDX quote POST endpoint with report data"""
    try:
        payload = {"report_data": "deadbeefcafebabe"}
        response = requests.post(f"{base_url}/tdx_quote", json=payload)
        print(f"TDX Quote POST: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Success: {data.get('success')}")
            print(f"  Quote type: {data.get('quote_type')}")
            print(f"  TCBInfo type: {data.get('tcb_info')}")
            return True
        elif response.status_code == 500 and no_tdx:
            expected = {
                "detail": {
                    "success": False,
                    "error": "Unix socket file /var/run/dstack.sock does not exist",
                    "quote_type": "tdx",
                }
            }
            if response.json() == expected:
                print("  Received expected error for missing TDX environment")
                return True
        else:
            print(f"  Error: {response.json()}")
            return False
    except Exception as e:
        print(f"TDX Quote POST failed: {e}")
        return False


def main():
    """Main test function"""
    parser = argparse.ArgumentParser(
        description="Test script for the attestation service endpoints"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8080",
        help="Base URL of the attestation service (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--no-tdx",
        action="store_true",
        default=False,
        help="Expect TDX environment to be unavailable (default: False)",
    )

    args = parser.parse_args()

    print(f"Testing attestation service at {args.base_url}")
    if args.no_tdx:
        print("Running in no-TDX mode (expecting TDX errors)")
    print("=" * 50)

    tests = [
        test_health_endpoint,
        test_tdx_quote_post,
    ]

    passed = 0
    for test in tests:
        if test(args.base_url, no_tdx=args.no_tdx):
            passed += 1

    print("=" * 50)
    print(f"Tests completed: {passed}/{len(tests)} passed")

    if passed == len(tests):
        exit(0)
    else:
        exit(1)


if __name__ == "__main__":
    main()
