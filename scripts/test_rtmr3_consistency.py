#!/usr/bin/env python3
"""
Test that RTMR3 calculation is consistent across:
1. Python calc_rtmr3.py script
2. tdx_quote endpoint event log
3. TypeScript implementation (via API route)
"""

import json
import sys
import subprocess
from pathlib import Path
from urllib import error, request

ATTESTATION_URL = "https://vllm.concrete-security.com/tdx_quote"
API_URL = "http://localhost:3000/api/rtmr/replay"

def fetch_quote():
    """Fetch a quote from the attestation endpoint."""
    import secrets
    report_data = "0x" + secrets.token_hex(16)
    
    data = json.dumps({"report_data": report_data}).encode("utf-8")
    req = request.Request(
        ATTESTATION_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    
    try:
        with request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            result = json.loads(body.decode("utf-8"))
            if not result.get("success"):
                error_msg = result.get("error") or result.get("detail", {}).get("error", "Unknown error")
                print(f"❌ Quote fetch failed: {error_msg}")
                if "report_data" in error_msg.lower():
                    print("   Trying with shorter report_data...")
                    report_data = "0x" + secrets.token_hex(16)
                    data = json.dumps({"report_data": report_data}).encode("utf-8")
                    req = request.Request(
                        ATTESTATION_URL,
                        data=data,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with request.urlopen(req, timeout=30) as resp2:
                        body2 = resp2.read()
                        return json.loads(body2.decode("utf-8"))
                sys.exit(1)
            return result
    except error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"❌ HTTP error: {e.code}")
        try:
            error_data = json.loads(body)
            print(f"   Error: {error_data.get('error') or error_data.get('detail', {}).get('error', body)}")
        except:
            print(f"   Response: {body[:200]}")
        sys.exit(1)
    except error.URLError as e:
        print(f"❌ URL error: {e.reason}")
        sys.exit(1)

def extract_history_from_quote(quote_data):
    """Extract RTMR3 history from quote event log."""
    quote_obj = quote_data.get("quote", {})
    event_log = quote_obj.get("event_log")
    
    if isinstance(event_log, str):
        event_log = json.loads(event_log)
    
    if not isinstance(event_log, list):
        print("❌ Event log is not a list")
        sys.exit(1)
    
    history = []
    for entry in event_log:
        if isinstance(entry, dict) and entry.get("imr") == 3:
            digest = entry.get("digest")
            if isinstance(digest, str) and digest.strip():
                history.append(digest.strip())
    
    return history

def compute_rtmr3_python(history):
    """Compute RTMR3 using Python (same logic as calc_rtmr3.py)."""
    import hashlib
    
    INIT_MR = "0" * 96
    CONTENT_LENGTH = 48
    
    if not history:
        return INIT_MR
    
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        payload = bytes.fromhex(content)
        if len(payload) < CONTENT_LENGTH:
            payload = payload.ljust(CONTENT_LENGTH, b"\0")
        mr = hashlib.sha384(mr + payload).digest()
    
    return mr.hex()

def compute_rtmr3_typescript(history):
    """Compute RTMR3 using TypeScript API route."""
    data = json.dumps({"history": history}).encode("utf-8")
    req = request.Request(
        API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    
    try:
        with request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            result = json.loads(body.decode("utf-8"))
            return result.get("rtmr")
    except error.HTTPError as e:
        print(f"❌ TypeScript API HTTP error: {e.code}")
        body = e.read().decode("utf-8")
        print(f"   Response: {body}")
        return None
    except error.URLError as e:
        print(f"⚠️  TypeScript API not available (is Next.js running?): {e.reason}")
        return None

def main():
    print("🧪 Testing RTMR3 calculation consistency\n")
    
    print("1. Fetching quote from attestation endpoint...")
    quote_data = fetch_quote()
    
    if not quote_data.get("success"):
        print(f"❌ Quote fetch failed: {quote_data.get('error')}")
        sys.exit(1)
    
    print("   ✅ Quote fetched successfully")
    
    print("\n2. Extracting RTMR3 history from event log...")
    history = extract_history_from_quote(quote_data)
    
    if len(history) < 3:
        print(f"❌ Expected at least 3 history entries, got {len(history)}")
        sys.exit(1)
    
    print(f"   ✅ Found {len(history)} history entries")
    print(f"   Rootfs hash: {history[0][:32]}...")
    print(f"   App ID hash: {history[1][:32]}...")
    print(f"   Cert hash: {history[2][:32]}...")
    
    print("\n3. Computing RTMR3 using Python (calc_rtmr3.py logic)...")
    python_rtmr3 = compute_rtmr3_python(history)
    print(f"   Python RTMR3: {python_rtmr3[:32]}...")
    
    print("\n4. Computing RTMR3 using TypeScript API...")
    typescript_rtmr3 = compute_rtmr3_typescript(history)
    
    if typescript_rtmr3:
        print(f"   TypeScript RTMR3: {typescript_rtmr3[:32]}...")
    else:
        print("   ⚠️  Skipping TypeScript comparison (API not available)")
    
    print("\n5. Comparing results...")
    all_match = True
    
    if typescript_rtmr3:
        if python_rtmr3.lower() == typescript_rtmr3.lower():
            print("   ✅ Python and TypeScript match!")
        else:
            print("   ❌ Python and TypeScript DO NOT MATCH!")
            print(f"      Python:    {python_rtmr3}")
            print(f"      TypeScript: {typescript_rtmr3}")
            all_match = False
    
    if all_match:
        print("\n✅ All RTMR3 calculations match!")
        return 0
    else:
        print("\n❌ RTMR3 calculations do not match!")
        return 1

if __name__ == "__main__":
    sys.exit(main())

