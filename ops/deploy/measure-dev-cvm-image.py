from __future__ import annotations

import argparse
import asyncio
import base64
import os
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import stat
import sys
import time
from typing import Any

from umbra_console.config import load_settings
from umbra_console.dns_provider.cloudflare import (
    CloudflareClient,
    CloudflareError,
    dstack_txt_name,
    gateway_cname_content,
)
from umbra_console.routes import render_dev_cvm_compose_config
from umbra_console.scheduler import (
    dstack_docker_pull_env,
    render_dev_cvm_shade_config,
)
from umbra_console.shade_provider.shade import ShadeClient, ShadeError
from umbra_console.tee_provider.phala import PhalaClient, PhalaError


DNS_RANDOM_TOKEN_CHARS = 26
UMBRA_CVM_NAME_PREFIX = "umbra-v0-cvm-"
MAX_SHADE_CERT_COMMON_NAME_CHARS = 64
DEFAULT_DEPLOY_TIMEOUT_SECONDS = 900
DEFAULT_POLICY_TIMEOUT_SECONDS = 900
MEASUREMENT_RETRY_SECONDS = 10
MOCK_SSH_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFmrXQi1v8gOqaroJ2uRiETCkPbo5fDkIwPN32SuOhY "
    "measure@umbra.invalid"
)
DUMMY_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUdMqujVY2gngKGsuCeiw0QfLwP4IwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWVW1icmEgTWVhc3VyZW1lbnQgTW9jazAgFw0yNjA4MDQxNDMx
NThaGA8yMTI2MDcxMTE0MzE1OFowITEfMB0GA1UEAwwWVW1icmEgTWVhc3VyZW1l
bnQgTW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCE6QiImV9wayyrpnUmt
XXoaYg8kBkWN3Li6zXllBIlMmxC1DviZ/2l/9FhveGSuSyE6GxO52Hd8DvWECayC
zyejUzBRMB0GA1UdDgQWBBSjXLJ18OGhfQyZf9mNmMvBXYkxADAfBgNVHSMEGDAW
gBSjXLJ18OGhfQyZf9mNmMvBXYkxADAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCICMNW+trnE5fEVpxhVF+pZZahsK1dhuqAfPpyne1DO+/AiEA4VlN
AGhKLjpdc3h+nfKvf8XWZIlpay+cdEOLedAZx0o=
-----END CERTIFICATE-----
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Deploy a direct Phala canary for a Dev CVM image, fetch its shade policy, "
            "and emit the observed TEE image measurement. Does not edit .env or Console DB."
        )
    )
    parser.add_argument("--image-ref", required=True, help="Digest-pinned Dev CVM image ref to measure.")
    parser.add_argument("--output", help="Path to write the release manifest JSON. Defaults to stdout only.")
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Leave the canary CVM and DNS records running for inspection.",
    )
    parser.add_argument("--name", help="Umbra-owned Phala canary name. Must start with umbra-v0-cvm-.")
    parser.add_argument("--fqdn", help="Canary FQDN. Defaults to cvm-<token>.$CLOUDFLARE_BASE_DOMAIN.")
    parser.add_argument(
        "--instance-type",
        help="Phala instance type. Defaults to DEV_CVM_DEFAULT_INSTANCE_TYPE/PHALA_DEFAULT_INSTANCE_TYPE.",
    )
    parser.add_argument("--region", help="Phala region. Defaults to DEV_CVM_DEFAULT_REGION/PHALA_REGION.")
    parser.add_argument("--deploy-timeout-seconds", type=float, default=DEFAULT_DEPLOY_TIMEOUT_SECONDS)
    parser.add_argument("--policy-timeout-seconds", type=float, default=DEFAULT_POLICY_TIMEOUT_SECONDS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = asyncio.run(measure(args))
        payload = json.dumps(manifest, indent=2, sort_keys=True)
        if args.output:
            write_private_text(Path(args.output), f"{payload}\n")
            print("measure-dev-cvm-image: wrote private release manifest", file=sys.stderr)
        else:
            print(payload)
    except ShadeError as exc:
        print(f"measure-dev-cvm-image: shade {exc.code}", file=sys.stderr)
        return 1
    except PhalaError as exc:
        print(f"measure-dev-cvm-image: phala {exc.code}", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - unexpected values and paths must not enter retained logs.
        print("measure-dev-cvm-image: failed; detailed diagnostics were suppressed", file=sys.stderr)
        return 1
    return 0


async def measure(args: argparse.Namespace) -> dict[str, Any]:
    if not is_digest_pinned_image_ref(args.image_ref):
        raise RuntimeError("--image-ref must be digest-pinned with @sha256:<digest>")
    raw = load_settings().raw
    token = random_token()
    base_domain = raw.get("CLOUDFLARE_BASE_DOMAIN", "").strip().strip(".").lower()
    if not base_domain and not args.fqdn:
        raise RuntimeError("CLOUDFLARE_BASE_DOMAIN is required when --fqdn is not supplied")

    name = args.name or f"{UMBRA_CVM_NAME_PREFIX}measure-{token[:16]}"
    if not name.startswith(UMBRA_CVM_NAME_PREFIX):
        raise RuntimeError(f"--name must start with {UMBRA_CVM_NAME_PREFIX}")
    fqdn = args.fqdn or f"cvm-{token}.{base_domain}"
    if len(fqdn) > MAX_SHADE_CERT_COMMON_NAME_CHARS:
        raise RuntimeError(
            f"canary FQDN is {len(fqdn)} characters; shade certificate common name limit is "
            f"{MAX_SHADE_CERT_COMMON_NAME_CHARS}: {fqdn}"
        )
    instance_type = (
        args.instance_type
        or raw.get("DEV_CVM_DEFAULT_INSTANCE_TYPE", "").strip()
        or raw.get("PHALA_DEFAULT_INSTANCE_TYPE", "").strip()
        or "tdx.small"
    )
    region = (
        args.region
        or raw.get("DEV_CVM_DEFAULT_REGION", "").strip()
        or raw.get("PHALA_REGION", "").strip()
        or "FR-PARIS-1"
    )

    app_id: str | None = None
    txt_record_id: str | None = None
    cname_record_id: str | None = None
    gateway_host: str | None = None

    try:
        snapshot = {"fqdn": fqdn, "instance_type": instance_type, "region": region}
        cloudflare = CloudflareClient.from_settings()
        compose_yaml = render_dev_cvm_compose_config({"image": args.image_ref})
        shade = ShadeClient.from_settings()
        shade_result = await shade.build(
            shade_config_yaml=render_dev_cvm_shade_config(snapshot, name=name),
            app_compose_yaml=compose_yaml,
        )

        deploy_env = measurement_env(raw)
        deploy_result = await PhalaClient.from_settings(timeout_seconds=args.deploy_timeout_seconds).deploy(
            name=name,
            compose_yaml=shade_result.compose_yaml,
            env=deploy_env,
            instance_type=instance_type,
            region=region,
        )
        app_id = deploy_result.app_id
        gateway_host = deploy_result.gateway_host
        print("measure-dev-cvm-image: canary deployed; waiting for attestation policy", file=sys.stderr)

        txt_record_id = await ensure_new_record_or_none(
            cloudflare,
            record_type="TXT",
            name=dstack_txt_name(fqdn),
            content=f"{app_id}:443",
        )
        cname_record_id = await ensure_new_record_or_none(
            cloudflare,
            record_type="CNAME",
            name=fqdn,
            content=gateway_cname_content(gateway_host),
        )

        policy = await generate_policy_with_retries(
            shade,
            domain=fqdn,
            deploy_compose_yaml=shade_result.compose_yaml,
            timeout_seconds=args.policy_timeout_seconds,
        )
        measurement = image_measurement_from_policy(policy)
        return {
            "component": "dev_cvm",
            "image_ref": args.image_ref,
            "image_measurement": measurement,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "canary": {
                "name": name,
                "fqdn": fqdn,
                "deployment_id": app_id,
                "gateway_host": gateway_host,
                "kept": args.keep,
            },
            "policy": {
                "expected_bootchain": policy.get("expected_bootchain"),
                "os_image_hash": policy.get("os_image_hash"),
            },
        }
    finally:
        if not args.keep:
            await cleanup_canary(app_id=app_id, txt_record_id=txt_record_id, cname_record_id=cname_record_id)


async def generate_policy_with_retries(
    shade: ShadeClient,
    *,
    domain: str,
    deploy_compose_yaml: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: ShadeError | None = None
    while True:
        try:
            result = await shade.generate_policy(
                domain=domain,
                deploy_compose_yaml=deploy_compose_yaml,
            )
            return result.policy
        except ShadeError as exc:
            last_error = exc
            append_debug_detail(exc)
            if time.monotonic() + MEASUREMENT_RETRY_SECONDS > deadline:
                raise RuntimeError(f"policy generation did not succeed before timeout: {exc.code}") from exc
            print(
                f"measure-dev-cvm-image: waiting for canary attestation endpoint ({exc.code})",
                file=sys.stderr,
            )
            await asyncio.sleep(MEASUREMENT_RETRY_SECONDS)
    raise RuntimeError(f"policy generation failed: {last_error.code if last_error else 'unknown'}")


def append_debug_detail(exc: ShadeError) -> None:
    """Opt-in operator diagnostics: append the already-scrubbed subprocess
    output to the owner-only file named by UMBRA_MEASURE_DEBUG_FILE. Retained
    logs stay clean; the scrubbed detail never reaches stdout/stderr."""
    path = os.environ.get("UMBRA_MEASURE_DEBUG_FILE", "").strip()
    if not path:
        return
    detail = getattr(exc, "output", None) or ""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(f"=== {time.strftime('%H:%M:%S')} {exc.code}\n{detail}\n")


async def cleanup_canary(*, app_id: str | None, txt_record_id: str | None, cname_record_id: str | None) -> None:
    cloudflare: CloudflareClient | None = None
    if txt_record_id or cname_record_id:
        try:
            cloudflare = CloudflareClient.from_settings()
        except CloudflareError as exc:
            print(f"measure-dev-cvm-image: Cloudflare cleanup skipped: {exc.code}", file=sys.stderr)
    if cloudflare is not None:
        for record_id in (cname_record_id, txt_record_id):
            if record_id:
                try:
                    await cloudflare.delete_record(record_id)
                except CloudflareError as exc:
                    print(
                        f"measure-dev-cvm-image: failed to delete canary DNS record: {exc.code}",
                        file=sys.stderr,
                    )
    if app_id:
        try:
            await PhalaClient.from_settings(timeout_seconds=120.0).delete(app_id)
        except PhalaError as exc:
            print(f"measure-dev-cvm-image: failed to delete canary deployment: {exc.code}", file=sys.stderr)


async def ensure_new_record_or_none(
    cloudflare: CloudflareClient,
    *,
    record_type: str,
    name: str,
    content: str,
) -> str | None:
    records = await cloudflare.find_records(name=name, record_type=record_type)
    if any(record.content == content for record in records):
        return None
    return await cloudflare.ensure_record(record_type=record_type, name=name, content=content)


def measurement_env(raw: dict[str, str]) -> dict[str, str]:
    env = {
        "SECURITY_CVM_FQDN": "measurement.invalid",
        "SECURITY_CVM_PROXY_PORT": "443",
        "SECURITY_CVM_PROXY_TOKEN": secrets.token_urlsafe(32),
        "SECURITY_CVM_CA_CERT_B64": b64_text(DUMMY_CA_PEM),
        "AUTHORIZED_SSH_KEYS_B64": b64_text(f"{MOCK_SSH_KEY}\n"),
        "SANDBOX_ENV_PLACEHOLDERS_B64": b64_text(""),
    }
    env.update(dstack_docker_pull_env(raw))
    return env


def image_measurement_from_policy(policy: dict[str, Any]) -> str:
    bootchain = policy.get("expected_bootchain")
    if not isinstance(bootchain, dict):
        raise RuntimeError("generated policy is missing expected_bootchain")
    measurement = bootchain.get("mrtd")
    if not isinstance(measurement, str) or not is_hex_measurement(measurement):
        raise RuntimeError("generated policy is missing a valid 96-character expected_bootchain.mrtd")
    return measurement.lower()


def is_hex_measurement(value: str) -> bool:
    return len(value) == 96 and all(char in "0123456789abcdefABCDEF" for char in value)


def is_digest_pinned_image_ref(value: str) -> bool:
    if "@sha256:" not in value:
        return False
    _, digest = value.rsplit("@sha256:", 1)
    return len(digest) == 64 and all(char in "0123456789abcdefABCDEF" for char in digest)


def random_token() -> str:
    return base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=").lower()[:DNS_RANDOM_TOKEN_CHARS]


def b64_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def write_private_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = path.open("w")
    try:
        fd.write(payload)
    finally:
        fd.close()
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


if __name__ == "__main__":
    raise SystemExit(main())
