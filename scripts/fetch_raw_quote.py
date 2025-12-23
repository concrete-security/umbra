#!/usr/bin/env python3
"""
Fetch a raw TDX quote from the attestation endpoint.

Usage:
    python fetch_raw_quote.py [--output output.json] [--attestation-url URL]
"""

import argparse
import json
import secrets
import sys
from pathlib import Path
from urllib import error, request

DEFAULT_ATTESTATION_URL = "https://vllm.concrete-security.com/tdx_quote"


def _generate_report_data() -> str:
    """Generate a random 32-byte report data."""
    return secrets.token_hex(32)


def fetch_quote(attestation_url: str, report_data: str | None = None) -> dict:
    """Fetch a quote from the attestation endpoint."""
    if report_data is None:
        report_data = _generate_report_data()
    
    payload = {"report_data": report_data}
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        attestation_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    
    try:
        with request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            result = json.loads(body.decode("utf-8"))
            if not result.get("success"):
                error_msg = result.get("error") or "Unknown error"
                raise RuntimeError(f"Attestation service responded with failure: {error_msg}")
            return result
    except error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            error_data = json.loads(body)
            error_msg = error_data.get("error") or error_data.get("detail", {}).get("error", body)
        except:
            error_msg = body[:200]
        raise RuntimeError(f"HTTP error {e.code}: {error_msg}")
    except error.URLError as e:
        raise RuntimeError(f"Unable to reach attestation service: {e.reason}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch a raw TDX quote from the attestation endpoint."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file path (default: print to stdout).",
    )
    parser.add_argument(
        "--attestation-url",
        default=DEFAULT_ATTESTATION_URL,
        help=f"Attestation endpoint URL (default: {DEFAULT_ATTESTATION_URL}).",
    )
    parser.add_argument(
        "--report-data",
        help="Optional hex-encoded report data (defaults to random 32-byte value).",
    )
    args = parser.parse_args()
    
    try:
        print(f"Fetching quote from {args.attestation_url}...", file=sys.stderr)
        quote_data = fetch_quote(args.attestation_url, args.report_data)
        
        output_json = json.dumps(quote_data, indent=2)
        
        if args.output:
            args.output.write_text(output_json)
            print(f"Quote saved to {args.output}", file=sys.stderr)
        else:
            print(output_json)
    except RuntimeError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

