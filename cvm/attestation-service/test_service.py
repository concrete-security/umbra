"""
Test script for the attestation service endpoints
"""

import requests
import sys


def test_health_endpoint(base_url):
    """Test the health endpoint"""
    try:
        response = requests.get(f"{base_url}/health")
        print(f"Health check: {response.status_code} - {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


def test_tdx_quote_post(base_url):
    """Test TDX quote POST endpoint with report data"""
    try:
        payload = {"report_data": "deadbeefcafebabe"}
        response = requests.post(f"{base_url}/tdx_quote", json=payload)
        print(f"TDX Quote POST: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Success: {data.get('success')}")
            print(f"  Quote type: {data.get('quote_type')}")
            return True
        elif response.status_code == 422:
            print(f"  Validation Error: {response.json()}")
            return False
        else:
            print(f"  Error: {response.json()}")
            return False
    except Exception as e:
        print(f"TDX Quote POST failed: {e}")
        return False


def main():
    """Main test function"""
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

    print(f"Testing attestation service at {base_url}")
    print("=" * 50)

    tests = [
        test_health_endpoint,
        test_tdx_quote_post,
    ]

    passed = 0
    for test in tests:
        if test(base_url):
            passed += 1

    print("=" * 50)
    print(f"Tests completed: {passed}/{len(tests)} passed")


if __name__ == "__main__":
    main()
