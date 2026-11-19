"""Inspect release-journey evidence inside the deployed Console container."""

import asyncio
import json
import os
import re
import sys
from uuid import UUID

import asyncpg
import yaml
from umbra_console.attestation import _full_app_compose_from_shade_policy
from umbra_console.config import asyncpg_dsn, load_settings


PIN_NAMES = (
    "SECURITY_CVM_IMAGE_REF",
    "SECURITY_CVM_IMAGE_MEASUREMENT",
    "DEV_CVM_IMAGE",
    "DEV_CVM_IMAGE_MEASUREMENT",
)
IMAGE = re.compile(r"ghcr\.io/concrete-security/[a-z0-9._/-]+@sha256:[0-9a-f]{64}")
MEASUREMENT = re.compile(r"[0-9a-f]{96}")
SERVICES = {
    "security": ("mitmproxy", "proxy-tunnel"),
    "dev": ("user-sandbox", "dev-egress-forwarder", "dev-tunnel"),
}


class EvidenceError(Exception):
    pass


def check_pins(pins):
    for name, value, pattern in zip(PIN_NAMES, pins, (IMAGE, MEASUREMENT, IMAGE, MEASUREMENT), strict=True):
        if not pattern.fullmatch(value) or os.environ.get(name) != value:
            raise EvidenceError(f"Console image pin mismatch for {name}")


def check_cvm(row, role, image, measurement, rtmr3):
    if (
        not row
        or row["expected_image_measurement"] != measurement
        or row["image_measurement"] != measurement
        or row["rtmr3_digest"] != rtmr3
        or row["attestation_verified_at"] is None
        or row["error_reason"] is not None
    ):
        raise EvidenceError(f"{role} CVM has no matching successful attestation")

    evidence = json.loads(row["evidence"] or "{}")
    policy = evidence.get("atls_policy", {}) if role == "security" else evidence
    deployed = evidence.get("deploy_compose_yaml")
    app_compose = _full_app_compose_from_shade_policy(policy) or {}
    attested = app_compose.get("docker_compose_file")
    if (
        not isinstance(attested, str)
        or not attested
        or attested != deployed
        or (role == "dev" and attested != policy.get("compose_template"))
    ):
        raise EvidenceError(f"{role} CVM has no matching attested Compose")

    services = yaml.safe_load(attested).get("services", {})
    if any(services.get(name, {}).get("image") != image for name in SERVICES[role]):
        raise EvidenceError(f"{role} CVM attested Compose image does not match the release lock")


async def check_database(args):
    action, entity_id, *evidence = args
    entity = UUID(entity_id)
    connection = await asyncpg.connect(asyncpg_dsn(load_settings().database_url), timeout=10, command_timeout=10)
    try:
        async with connection.transaction(readonly=True):
            if action == "fresh":
                existing = await connection.fetchval(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM security_cvms
                        WHERE entity_id = $1 AND deleted_at IS NULL AND state <> 'TERMINATED'
                        UNION ALL
                        SELECT 1 FROM cvms
                        WHERE entity_id = $1 AND deleted_at IS NULL AND state <> 'TERMINATED'
                    )
                    """,
                    entity,
                )
                if existing:
                    raise EvidenceError("staging entity already has a Security or Dev CVM; use an empty test entity")
                return

            cvm_id, image, measurement, rtmr3 = evidence
            if not MEASUREMENT.fullmatch(rtmr3):
                raise EvidenceError(f"{action} CVM has an invalid attested RTMR3")
            # The table and column are fixed by the two supported roles.
            table, field = ("security_cvms", "metadata") if action == "security" else ("cvms", "atls_policy_bundle")
            row = await connection.fetchrow(
                f"""
                SELECT expected_image_measurement, image_measurement, rtmr3_digest,
                       attestation_verified_at, error_reason, {field} AS evidence
                FROM {table}
                WHERE entity_id = $1 AND id = $2 AND deleted_at IS NULL AND state = 'RUNNING'
                """,
                entity,
                UUID(cvm_id),
            )
            check_cvm(row, action, image, measurement, rtmr3)
    finally:
        await connection.close()


def main(args):
    try:
        action, *values = args
        if action == "pins" and len(values) == 4:
            check_pins(values)
        elif (action == "fresh" and len(values) == 1) or (action in SERVICES and len(values) == 5):
            asyncio.run(check_database(args))
        else:
            raise EvidenceError("invalid release CVM check")
    except EvidenceError as exc:
        print(f"release qualification: {exc}", file=sys.stderr)
        return 1
    except (AttributeError, KeyError, TypeError, ValueError, yaml.YAMLError,
            asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError):
        # Never print the DSN, environment, quote, or resolved Compose.
        print("release qualification: could not read verified CVM evidence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
