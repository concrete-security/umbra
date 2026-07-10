"""Real-Postgres integration test for the per-user-secret SC control path.

Every other module under ``console/tests`` drives the handlers with *fake*
asyncpg connections, so the SQL string and the migration DDL are only ever
validated by reading. This module is the exception: it applies the full Alembic
stack to a throwaway database and runs the *actual* ``list_sc_control_cvms``
query. It exists to cover the two runtime surfaces the fake-connection tests
cannot reach:

1. **Migration ``0026_user_secret_material``** — that ``CREATE TABLE
   user_secret_material`` (with the ``ciphertext LIKE 'v1:%'`` and
   ``jsonb_typeof(allowed_hosts) = 'array'`` CHECKs) and the two
   ``ALTER TYPE audit_action ADD VALUE`` statements actually apply on top of
   0025, inside Alembic's per-migration transaction, on the deployment's
   Postgres. ``make check`` only runs ``alembic heads`` (graph, not upgrade).

2. **``list_sc_control_cvms``** — that the added ``c.owner_id`` in the
   SELECT/GROUP BY plus the correlated ``owner_secret_material`` subquery are
   valid SQL, that the GROUP BY holds for 0/1/N attached profiles, and that the
   owner's secret material aggregates and hydrates into the merged policy end to
   end. A missing GROUP BY column or a bad subquery would otherwise only surface
   at the first live Security CVM poll.

The whole ``entries`` wire-shape contract (each entry's keys are exactly
``{cvm_id, fqdn, proxy_token_hash, merged_policy, policy_version, updated_at}``)
is asserted end to end, because the Security CVM's policy parser rejects unknown
injection fields (``deny_all``) — no key may appear or disappear.

**Opt-in.** Set ``CONCRETE_TEST_DATABASE_URL`` to a Postgres DSN whose role may
``CREATE DATABASE``; the test creates and drops a uniquely-named throwaway
database per run, so existing app data is never touched. Without the env var the
module skips, so the default DB-less ``make test`` gate stays green. Boot an
ephemeral Postgres and run it with ``make test-console-db``.
"""

import asyncio
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

import pytest

import asyncpg
from asyncpg import exceptions as pg_errors

CONSOLE_DIR = Path(__file__).resolve().parents[1]
DSN_ENV = "CONCRETE_TEST_DATABASE_URL"
# 32-byte all-zero KEK, base64url without padding — identical to the fixture the
# fake-connection tests use, so seed ciphertext round-trips under the same key.
KEK_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _base_dsn() -> str | None:
    return os.environ.get(DSN_ENV, "").strip() or None


pytestmark = pytest.mark.skipif(
    _base_dsn() is None,
    reason=f"set {DSN_ENV} to a Postgres DSN (role may CREATE DATABASE) to run; see module docstring / `make test-console-db`",
)


# --- DSN helpers ---------------------------------------------------------------
# asyncpg wants the bare `postgresql://` scheme; SQLAlchemy/Alembic want the
# `postgresql+asyncpg://` driver form (see console/alembic/env.py).


def _asyncpg_form(dsn: str) -> str:
    prefix = "postgresql+asyncpg://"
    return "postgresql://" + dsn[len(prefix) :] if dsn.startswith(prefix) else dsn


def _sqlalchemy_form(dsn: str) -> str:
    prefix = "postgresql://"
    return "postgresql+asyncpg://" + dsn[len(prefix) :] if dsn.startswith(prefix) else dsn


def _with_database(dsn: str, dbname: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, parts.fragment))


async def _admin_execute(base_dsn: str, sql: str, *args) -> None:
    conn = await asyncpg.connect(_asyncpg_form(base_dsn))
    try:
        await conn.execute(sql, *args)
    finally:
        await conn.close()


def _alembic_upgrade_head(db_dsn: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["DATABASE_URL"] = _sqlalchemy_form(db_dsn)
    # Mirrors the real deploy path (console/entrypoint.sh: `alembic upgrade head`)
    # and `make check` (`cd console && python -m alembic ...`): alembic.ini and the
    # `alembic/` script dir are resolved relative to the console working directory.
    return subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(CONSOLE_DIR),
        env=env,
        capture_output=True,
        text=True,
    )


# --- Seed identifiers and policies ---------------------------------------------

ENTITY_ID = uuid.UUID("11111111-1111-4111-8111-000000000001")
OWNER_FULL = uuid.UUID("11111111-1111-4111-8111-0000000000a1")  # owns two user secrets
OWNER_NONE = uuid.UUID("11111111-1111-4111-8111-0000000000a2")  # owns none
SC_ID = uuid.UUID("11111111-1111-4111-8111-0000000000f1")
PROF_SLACK = uuid.UUID("11111111-1111-4111-8111-000000000051")
PROF_GITHUB = uuid.UUID("11111111-1111-4111-8111-000000000052")
PROF_DEST = uuid.UUID("11111111-1111-4111-8111-000000000053")
CVM_0 = uuid.UUID("11111111-1111-4111-8111-000000000031")  # 0 attached profiles
CVM_1 = uuid.UUID("11111111-1111-4111-8111-000000000032")  # 1 attached profile
CVM_N = uuid.UUID("11111111-1111-4111-8111-000000000033")  # N (2) attached profiles
CVM_NOOWNER = uuid.UUID("11111111-1111-4111-8111-000000000034")  # owner has no secrets

SLACK_VALUE = "xoxp-INTEG-slack-9f3a"
GITHUB_VALUE = "ghp-INTEG-github-7b2c"
GH_APP_VALUE = "profile-gh-app-secret"
FIXED_TS = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)

WIRE_KEYS = {"cvm_id", "fqdn", "proxy_token_hash", "merged_policy", "policy_version", "updated_at"}


def _value_from_injection(inj_id: str, secret_name: str, host: str) -> dict:
    return {
        "id": inj_id,
        "match": {"scheme": "https", "host": host},
        "type": "request_header",
        "header": "authorization",
        "value_from": {"user_secret": secret_name},
        "value_template": "Bearer ${secret}",
    }


SLACK_POLICY = {"secret_injections": [_value_from_injection("slack-token", "slack-user-token", "api.slack.com")]}
GITHUB_POLICY = {
    "secret_injections": [
        _value_from_injection("gh-token", "github-pat", "api.github.com"),
        # No value_from: resolves via the profile's own profile_secret_material,
        # exercising the second correlated subquery alongside the owner one.
        {"id": "gh-app", "type": "request_header", "header": "x-github-app"},
    ]
}
DEST_RULE = {
    "id": "anthropic",
    "scheme": "https",
    "host": "api.anthropic.com",
    "ports": [443],
    "methods": ["GET"],
    "path_prefixes": ["/"],
}
DEST_POLICY = {"allowed_destinations": [DEST_RULE]}


def _scan_payload_for_key(value, key) -> bool:
    if isinstance(value, dict):
        return key in value or any(_scan_payload_for_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_scan_payload_for_key(item, key) for item in value)
    return False


async def _seed(conn: asyncpg.Connection) -> None:
    from concrete_console.profile_secrets import encrypt_profile_secret_value, encrypt_user_secret_value

    await conn.execute(
        "INSERT INTO entities (id, name, domain) VALUES ($1, $2, $3)",
        ENTITY_ID,
        "IntegEntity",
        "integ.example.com",
    )
    await conn.execute(
        "INSERT INTO users (id, email, entity_id) VALUES ($1, $2, $4), ($3, $5, $4)",
        OWNER_FULL,
        "full@integ.example.com",
        OWNER_NONE,
        ENTITY_ID,
        "none@integ.example.com",
    )

    # OWNER_FULL's user secrets. Encrypt with the same UUID stored on the row so
    # the owner-bound AAD matches at decrypt time (c.owner_id comes back as UUID).
    for name, host, value in [
        ("slack-user-token", "api.slack.com", SLACK_VALUE),
        ("github-pat", "*.github.com", GITHUB_VALUE),
    ]:
        await conn.execute(
            "INSERT INTO user_secret_material (user_id, name, ciphertext, allowed_hosts) VALUES ($1, $2, $3, $4::jsonb)",
            OWNER_FULL,
            name,
            encrypt_user_secret_value(user_id=OWNER_FULL, name=name, value=value),
            json.dumps([host]),
        )

    for pid, name, policy in [
        (PROF_SLACK, "slack", SLACK_POLICY),
        (PROF_GITHUB, "github", GITHUB_POLICY),
        (PROF_DEST, "dest", DEST_POLICY),
    ]:
        await conn.execute(
            "INSERT INTO entity_profiles (id, entity_id, name, policy) VALUES ($1, $2, $3, $4::jsonb)",
            pid,
            ENTITY_ID,
            name,
            json.dumps(policy),
        )
    await conn.execute(
        "INSERT INTO profile_secret_material (profile_id, injection_id, ciphertext) VALUES ($1, $2, $3)",
        PROF_GITHUB,
        "gh-app",
        encrypt_profile_secret_value(profile_id=PROF_GITHUB, injection_id="gh-app", value=GH_APP_VALUE),
    )

    for cid, owner, policy_version in [
        (CVM_0, OWNER_FULL, 5),
        (CVM_1, OWNER_FULL, 6),
        (CVM_N, OWNER_FULL, 7),
        (CVM_NOOWNER, OWNER_NONE, 8),
    ]:
        await conn.execute(
            """
            INSERT INTO cvms (id, entity_id, owner_id, state, fqdn, instance_type, policy_version, updated_at)
            VALUES ($1, $2, $3, 'RUNNING', $4, $5, $6, $7)
            """,
            cid,
            ENTITY_ID,
            owner,
            f"{cid.hex[-8:]}.integ.example.com",
            "tdx.medium",
            policy_version,
            FIXED_TS,
        )
        # The service_principal_tokens parent-exists trigger requires the CVM row first.
        await conn.execute(
            """
            INSERT INTO service_principal_tokens (principal_type, principal_id, purpose, token_hash)
            VALUES ('dev_cvm', $1, 'PROXY_AUTH', $2)
            """,
            cid,
            f"proxy-{cid.hex}",
        )

    for cid, pid in [(CVM_1, PROF_SLACK), (CVM_N, PROF_GITHUB), (CVM_N, PROF_DEST), (CVM_NOOWNER, PROF_SLACK)]:
        await conn.execute("INSERT INTO cvm_profiles (cvm_id, profile_id) VALUES ($1, $2)", cid, pid)


async def _assert_migration_ddl(conn: asyncpg.Connection) -> None:
    """Migration 0026 applied its enum extension and both table CHECKs."""
    labels = {
        row["enumlabel"]
        for row in await conn.fetch(
            "SELECT enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'audit_action'"
        )
    }
    assert {"USER_SECRET_SET", "USER_SECRET_DELETED"} <= labels

    # CHECK (ciphertext LIKE 'v1:%') — a non-v1 envelope is rejected.
    with pytest.raises(pg_errors.CheckViolationError):
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO user_secret_material (user_id, name, ciphertext, allowed_hosts) VALUES ($1, $2, $3, $4::jsonb)",
                OWNER_FULL,
                "ddl-bad-ciphertext",
                "plaintext-not-v1",
                json.dumps(["api.slack.com"]),
            )

    # CHECK (jsonb_typeof(allowed_hosts) = 'array') — a non-array is rejected
    # (ciphertext here is a valid v1 envelope so only the hosts CHECK can fire).
    with pytest.raises(pg_errors.CheckViolationError):
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO user_secret_material (user_id, name, ciphertext, allowed_hosts) VALUES ($1, $2, $3, $4::jsonb)",
                OWNER_FULL,
                "ddl-bad-hosts",
                "v1:not-real-but-shaped",
                json.dumps({"not": "an-array"}),
            )

    # PRIMARY KEY (user_id, name) — a duplicate name for the same owner is rejected.
    with pytest.raises(pg_errors.UniqueViolationError):
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO user_secret_material (user_id, name, ciphertext, allowed_hosts) VALUES ($1, $2, $3, $4::jsonb)",
                OWNER_FULL,
                "slack-user-token",
                "v1:duplicate",
                json.dumps(["api.slack.com"]),
            )


# This expression is intentionally the same correlated subquery as
# list_sc_control_cvms's `owner_secret_material`; keep it in lock-step with the
# handler so this directly pins the aggregation shape merge consumes.
_OWNER_MATERIAL_SQL = """
    SELECT COALESCE(
        (
            SELECT jsonb_object_agg(
                       usm.name,
                       jsonb_build_object('ciphertext', usm.ciphertext, 'allowed_hosts', usm.allowed_hosts)
                   )
            FROM user_secret_material usm
            WHERE usm.user_id = $1
        ),
        '{}'::jsonb
    )::text
"""


async def _assert_owner_material_aggregation(conn: asyncpg.Connection) -> None:
    # 0 owner secrets -> COALESCE to '{}'.
    assert json.loads(await conn.fetchval(_OWNER_MATERIAL_SQL, OWNER_NONE)) == {}

    # N owner secrets -> keyed by name, each carrying ciphertext + allowed_hosts.
    full = json.loads(await conn.fetchval(_OWNER_MATERIAL_SQL, OWNER_FULL))
    assert set(full) == {"slack-user-token", "github-pat"}
    assert full["slack-user-token"]["allowed_hosts"] == ["api.slack.com"]
    assert full["github-pat"]["allowed_hosts"] == ["*.github.com"]
    assert full["slack-user-token"]["ciphertext"].startswith("v1:")
    assert full["github-pat"]["ciphertext"].startswith("v1:")


def _assert_wire_shape_and_merge(body: dict, response: SimpleNamespace) -> None:
    entries = {entry["cvm_id"]: entry for entry in body["entries"]}
    # GROUP BY holds across 0/1/N attached profiles: one entry per RUNNING CVM,
    # no SQL error, none dropped or duplicated by the jsonb_agg/GROUP BY.
    assert set(entries) == {str(CVM_0), str(CVM_1), str(CVM_N), str(CVM_NOOWNER)}

    for cvm_id, entry in entries.items():
        assert set(entry) == WIRE_KEYS, cvm_id
        assert isinstance(entry["updated_at"], str) and entry["updated_at"].endswith("Z")

    # Scalar columns flow through untouched.
    assert entries[str(CVM_0)]["proxy_token_hash"] == f"proxy-{CVM_0.hex}"
    assert entries[str(CVM_0)]["policy_version"] == 5

    # 0 attached profiles: empty merge. Owner has secrets but nothing references them.
    m0 = entries[str(CVM_0)]["merged_policy"]
    assert m0["secret_injections"] == []
    assert m0["allowed_destinations"] == []
    assert m0["blocked_destinations"] == []
    assert m0["secret_patterns"] == []
    assert m0["sandbox_env"] == []

    # 1 attached profile: value_from resolves against the owner's slack secret.
    inj1 = entries[str(CVM_1)]["merged_policy"]["secret_injections"]
    assert len(inj1) == 1
    assert inj1[0]["id"] == "slack-token"
    assert inj1[0]["value"] == SLACK_VALUE
    assert inj1[0]["value_template"] == "Bearer ${secret}"
    assert "value_from" not in inj1[0]

    # N attached profiles: union of both profiles' injections (owner value_from +
    # profile-scoped profile_secret_material) and allowed_destinations.
    mN = entries[str(CVM_N)]["merged_policy"]
    by_id = {inj["id"]: inj for inj in mN["secret_injections"]}
    assert by_id["gh-token"]["value"] == GITHUB_VALUE  # owner value_from resolved
    assert by_id["gh-app"]["value"] == GH_APP_VALUE  # profile_secret_material resolved
    assert all("value_from" not in inj for inj in mN["secret_injections"])
    assert DEST_RULE in mN["allowed_destinations"]  # profile_policies aggregated across N

    # Owner has no user_secret_material: the value_from injection is omitted
    # (fail-closed), proving the COALESCE '{}' owner-material path.
    assert entries[str(CVM_NOOWNER)]["merged_policy"]["secret_injections"] == []

    # Leak guards: no unresolved value_from reaches the wire, and an owner secret
    # only appears on that owner's referencing CVM (not, e.g., CVM_0 or CVM_NOOWNER).
    assert not _scan_payload_for_key(body, "value_from")
    serialized = json.dumps(body)
    assert serialized.count(SLACK_VALUE) == 1
    assert serialized.count(GITHUB_VALUE) == 1
    assert response.headers["ETag"].startswith('"')


async def _run_assertions(db_dsn: str) -> None:
    from concrete_console.routes_internal import list_sc_control_cvms

    pool = await asyncpg.create_pool(_asyncpg_form(db_dsn), min_size=1, max_size=4)
    try:
        async with pool.acquire() as conn:
            await _seed(conn)
            await _assert_migration_ddl(conn)
            await _assert_owner_material_aggregation(conn)

        response = SimpleNamespace(headers={})
        principal = SimpleNamespace(principal_id=SC_ID, entity_id=ENTITY_ID)
        body = await list_sc_control_cvms(
            response=response,
            if_none_match=None,
            current_principal=principal,
            pool=pool,
        )
        assert isinstance(body, dict)
        _assert_wire_shape_and_merge(body, response)
    finally:
        await pool.close()


def test_sc_control_query_and_migration_against_real_postgres(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", KEK_B64)
    base = _base_dsn()
    assert base is not None  # guarded by pytestmark
    dbname = f"concrete_itest_{uuid.uuid4().hex}"

    asyncio.run(_admin_execute(base, f'CREATE DATABASE "{dbname}"'))
    child_dsn = _with_database(base, dbname)
    try:
        proc = _alembic_upgrade_head(child_dsn)
        assert proc.returncode == 0, f"alembic upgrade head failed:\n{proc.stdout}\n{proc.stderr}"
        asyncio.run(_run_assertions(child_dsn))
    finally:
        asyncio.run(
            _admin_execute(
                base,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                dbname,
            )
        )
        asyncio.run(_admin_execute(base, f'DROP DATABASE IF EXISTS "{dbname}"'))
