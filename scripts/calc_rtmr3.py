#!/usr/bin/env python3
"""
Calculate the RTMR3 digest expected for a CVM build.

This mirrors the attestation math performed by dstack's event log replay so
that we can sanity-check quotes or pre-compute publishable values.

Usage:
    python calc_rtmr3.py by-file --rootfs-cpio <rootfs.cpio> --compose <docker-compose.yml> --ca-cert <ca.cert> [--show-components]
    python calc_rtmr3.py by-vm --images-dir <images-dir> --vm-dir <vm-dir> [--show-components]
    python calc_rtmr3.py by-tee [--attestation-url https://vllm.concrete-security.com/tdx_quote] [--report-data <hex>] [--show-components]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, Iterable, List
from urllib import error, request
import sys

INIT_MR = "0" * 96  # 48 zeroed bytes, matching dstack INIT_MR
DEFAULT_ATTESTATION_URL = "https://vllm.concrete-security.com/tdx_quote"
IMR3_INDEX = 3


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def rtmr_replay(history: list[str]) -> str:
    """
    Replay the RTMR history to calculate the final RTMR value.
    """
    if not history:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        payload = bytes.fromhex(content)
        if len(payload) < 48:
            payload = payload.ljust(48, b"\0")
        mr = hashlib.sha384(mr + payload).digest()
    return mr.hex()


def calc_rtmr3(rootfs_hash: str, app_id: str, ca_cert_hash: str) -> str:
    """
    Calculate the RTMR3 hash from the given rootfs hash, app id and CA certificate hash.
    """
    return rtmr_replay([rootfs_hash, app_id, ca_cert_hash])


def _generate_report_data() -> str:
    return secrets.token_hex(32)


def _post_json(url: str, payload: dict[str, Any]) -> Any:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            try:
                return json.loads(body.decode("utf-8"))
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise RuntimeError("Attestation service returned invalid JSON.") from exc
    except error.HTTPError as exc:
        raise RuntimeError(f"Attestation request failed with status {exc.code}.") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach attestation service: {exc.reason}.") from exc


def _parse_event_log(raw: Any) -> List[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Event log payload is not valid JSON.") from exc
        if not isinstance(parsed, list):
            raise RuntimeError("Event log payload is not a list.")
        return parsed
    if isinstance(raw, list):
        return raw
    raise RuntimeError("Event log payload is not in a recognized format.")


def _extract_history(entries: Iterable[dict[str, Any]], imr_index: int) -> list[str]:
    history: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("imr") != imr_index:
            continue
        digest = entry.get("digest")
        if isinstance(digest, str) and digest.strip():
            history.append(digest.strip())
    return history


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculate the RTMR3 hash using local artifacts, VM metadata, or a live attestation quote."
    )
    parser.add_argument(
        "mode",
        choices=["by-file", "by-vm", "by-tee"],
        help="Select direct file hashing, VM metadata replay, or live attestation replay.",
    )
    parser.add_argument("--rootfs-cpio", type=Path, help="The rootfs.cpio file to use.")
    parser.add_argument("--compose", type=Path, help="The docker-compose.yml file to use.")
    parser.add_argument("--ca-cert", type=Path, help="The KMS CA certificate to use.")
    parser.add_argument("--images-dir", type=Path, help="The directory containing the VM images to use.")
    parser.add_argument("--vm-dir", type=Path, help="The directory of a deployed VM.")
    parser.add_argument(
        "--attestation-url",
        default=DEFAULT_ATTESTATION_URL,
        help=f"Attestation endpoint exposing /tdx_quote (default: {DEFAULT_ATTESTATION_URL}).",
    )
    parser.add_argument(
        "--report-data",
        help="Optional hex-encoded report data to send to the attestation endpoint (defaults to a random 32-byte value).",
    )
    parser.add_argument(
        "--show-components",
        action="store_true",
        help="Output component hashes (rootfs, app_id, ca_cert) in addition to RTMR3.",
    )
    args = parser.parse_args()

    def emit_component(label: str, value: str) -> None:
        if args.show_components:
            print(f"{label}={value}", file=sys.stderr)

    if args.mode == "by-file":
        if not args.rootfs_cpio or not args.compose or not args.ca_cert:
            parser.error("--rootfs-cpio, --compose and --ca-cert are required for by-file mode.")
        rootfs_hash = _sha256_file(args.rootfs_cpio)
        app_id = _sha256_file(args.compose)
        ca_cert_hash = _sha256_file(args.ca_cert)
        rtmr3 = calc_rtmr3(rootfs_hash, app_id, ca_cert_hash)
        emit_component("NEXT_PUBLIC_EXPECTED_ROOTFS_HASH", rootfs_hash)
        emit_component("NEXT_PUBLIC_EXPECTED_APP_ID_HASH", app_id)
    elif args.mode == "by-vm":
        if not args.images_dir or not args.vm_dir:
            parser.error("--images-dir and --vm-dir are required for by-vm mode.")
        vm_config = json.loads((args.vm_dir / "config.json").read_text())
        image_dir = args.images_dir / vm_config["image"]
        image_metadata = json.loads((image_dir / "metadata.json").read_text())
        rootfs_hash = image_metadata["rootfs_hash"]
        compose_file = args.vm_dir / "shared" / "docker-compose.yaml"
        ca_cert_file = args.vm_dir / "shared" / "certs" / "ca.cert"
        app_id = _sha256_file(compose_file)
        ca_cert_hash = _sha256_file(ca_cert_file)
        rtmr3 = calc_rtmr3(rootfs_hash, app_id, ca_cert_hash)
        emit_component("NEXT_PUBLIC_EXPECTED_ROOTFS_HASH", rootfs_hash)
        emit_component("NEXT_PUBLIC_EXPECTED_APP_ID_HASH", app_id)
    else:
        report_data = args.report_data.strip() if args.report_data else _generate_report_data()
        quote = _post_json(args.attestation_url, {"report_data": report_data})
        if not quote.get("success"):
            raise RuntimeError(f"Attestation service responded with failure: {quote.get('error')!r}")
        quote_data = quote.get("quote")
        if not isinstance(quote_data, dict):
            raise RuntimeError("Quote response did not contain a valid quote object.")
        event_log_entries = _parse_event_log(quote_data.get("event_log"))
        history = _extract_history(event_log_entries, IMR3_INDEX)
        if not history:
            raise RuntimeError("Event log did not contain any IMR3 entries.")
        if len(history) < 3:
            raise RuntimeError(f"Event log should contain at least 3 entries, found {len(history)}.")
        rootfs_hash_full = history[0]
        app_id_full = history[1]
        ca_cert_hash = history[2]
        rootfs_hash = (rootfs_hash_full[:64] if len(rootfs_hash_full) >= 64 else rootfs_hash_full).lower()
        app_id = (app_id_full[:64] if len(app_id_full) >= 64 else app_id_full).lower()
        rtmr3 = rtmr_replay(history)
        emit_component("NEXT_PUBLIC_EXPECTED_ROOTFS_HASH", rootfs_hash)
        emit_component("NEXT_PUBLIC_EXPECTED_APP_ID_HASH", app_id)

    print(rtmr3)


if __name__ == "__main__":
    main()
