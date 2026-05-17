from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg

from concrete_console.audit import insert_audit_event
from concrete_console.config import asyncpg_dsn, load_settings
from concrete_console.sessions import issue_token_pair

BOOTSTRAP_PERMISSIONS = (
    "PLATFORM_OPERATOR",
    "USER_MANAGE",
    "PERMISSION_MANAGE",
    "AUDIT_VIEW",
)


def email_domain(email: str) -> str:
    parts = email.rsplit("@", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("admin email must contain a local part and domain")
    return parts[1].lower()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap the first Concrete Console admin")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-name", default="")
    parser.add_argument("--entity-name", default="")
    parser.add_argument("--default-profile", default="default")
    parser.add_argument(
        "--session-file",
        default="",
        help="Optional path for a CLI session.json for the bootstrap platform operator.",
    )
    return parser.parse_args()


async def ensure_entity(conn: asyncpg.Connection, *, name: str, domain: str) -> tuple[UUID, bool]:
    entity_id = await conn.fetchval("SELECT id FROM entities WHERE domain = $1", domain)
    if entity_id:
        return entity_id, False

    entity_id = uuid4()
    await conn.execute(
        """
        INSERT INTO entities (id, name, domain)
        VALUES ($1, $2, $3)
        """,
        entity_id,
        name or domain,
        domain,
    )
    return entity_id, True


async def has_permission_manager(conn: asyncpg.Connection, entity_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            """
            SELECT 1
            FROM users u
            JOIN user_permissions up ON up.user_id = u.id
            WHERE u.entity_id = $1
              AND u.deleted_at IS NULL
              AND up.permission = 'PERMISSION_MANAGE'
            LIMIT 1
            """,
            entity_id,
        )
    )


async def create_admin(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID,
    email: str,
    name: str,
    default_profile: str,
) -> UUID:
    user_id = uuid4()
    await conn.execute(
        """
        INSERT INTO users (id, email, name, entity_id)
        VALUES ($1, $2, $3, $4)
        """,
        user_id,
        email,
        name,
        entity_id,
    )

    for permission in BOOTSTRAP_PERMISSIONS:
        await conn.execute(
            """
            INSERT INTO user_permissions (user_id, permission)
            VALUES ($1, $2)
            """,
            user_id,
            permission,
        )

    profile_id = uuid4()
    await conn.execute(
        """
        INSERT INTO entity_profiles (id, entity_id, name, description, policy)
        VALUES ($1, $2, $3, '', '{}'::jsonb)
        """,
        profile_id,
        entity_id,
        default_profile,
    )
    await conn.execute(
        """
        INSERT INTO profile_users (profile_id, user_id)
        VALUES ($1, $2)
        """,
        profile_id,
        user_id,
    )

    await insert_audit_event(
        conn,
        entity_id=entity_id,
        actor_id=None,
        actor_email="system@bootstrap",
        action="USER_REGISTERED",
        target_type="user",
        target_id=user_id,
        after={"email": email, "name": name, "entity_id": str(entity_id)},
    )
    for permission in BOOTSTRAP_PERMISSIONS:
        await insert_audit_event(
            conn,
            entity_id=entity_id,
            actor_id=None,
            actor_email="system@bootstrap",
            action="PERMISSION_GRANTED",
            target_type="user",
            target_id=user_id,
            after={"permission": permission},
        )
    await insert_audit_event(
        conn,
        entity_id=entity_id,
        actor_id=None,
        actor_email="system@bootstrap",
        action="PROFILE_CREATED",
        target_type="profile",
        target_id=profile_id,
        after={"name": default_profile},
    )
    await insert_audit_event(
        conn,
        entity_id=entity_id,
        actor_id=None,
        actor_email="system@bootstrap",
        action="PROFILE_USER_ASSIGNED",
        target_type="profile",
        target_id=profile_id,
        after={"user_id": str(user_id)},
    )
    return user_id


async def find_active_platform_operator(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID,
    email: str,
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT
            u.id,
            u.email,
            e.id AS entity_id,
            e.name AS entity_name
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        JOIN user_permissions up ON up.user_id = u.id
        WHERE u.entity_id = $1
          AND lower(u.email) = lower($2)
          AND u.deactivated_at IS NULL
          AND u.deleted_at IS NULL
          AND up.permission = 'PLATFORM_OPERATOR'
        LIMIT 1
        """,
        entity_id,
        email,
    )


def format_session_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def write_session_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    tmp_path = path.with_name(f".{path.name}.{uuid4()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


async def issue_bootstrap_session(
    conn: asyncpg.Connection,
    *,
    user_row: asyncpg.Record,
    session_file: Path,
) -> None:
    token_pair = await issue_token_pair(conn, user_id=user_row["id"])
    await insert_audit_event(
        conn,
        entity_id=token_pair.entity_id,
        actor_id=token_pair.user_id,
        actor_email=token_pair.actor_email,
        action="AUTH_SESSION_ISSUED",
        target_type="user",
        target_id=token_pair.user_id,
        after={"refresh_jti": str(token_pair.refresh_jti), "source": "bootstrap"},
    )
    payload = {
        "access_token": token_pair.response["access_token"],
        "refresh_token": token_pair.response["refresh_token"],
        "user_id": str(user_row["id"]),
        "email": user_row["email"],
        "entity": {
            "id": str(user_row["entity_id"]),
            "name": user_row["entity_name"],
        },
        "expires_at": format_session_time(token_pair.access_expires_at),
        "refresh_expires_at": format_session_time(token_pair.refresh_expires_at),
    }
    write_session_file(session_file, payload)


async def run() -> int:
    if os.environ.get("CONCRETE_ALLOW_BOOTSTRAP") != "true":
        print("[usage] set CONCRETE_ALLOW_BOOTSTRAP=true to run bootstrap", file=sys.stderr)
        return 2

    args = parse_args()
    domain = args.domain.strip().lower()
    admin_email = args.admin_email.strip().lower()
    session_file = Path(args.session_file) if args.session_file.strip() else None
    try:
        admin_domain = email_domain(admin_email)
    except ValueError as exc:
        print(f"[usage] {exc}", file=sys.stderr)
        return 2

    if admin_domain != domain:
        print("[usage] admin email domain must match --domain", file=sys.stderr)
        return 2

    settings = load_settings()
    conn = await asyncpg.connect(asyncpg_dsn(settings.database_url))
    try:
        async with conn.transaction():
            entity_id, entity_created = await ensure_entity(
                conn,
                name=args.entity_name.strip() or domain,
                domain=domain,
            )
            if await has_permission_manager(conn, entity_id):
                print("bootstrap already complete")
            else:
                if entity_created:
                    await insert_audit_event(
                        conn,
                        entity_id=entity_id,
                        actor_id=None,
                        actor_email="system@bootstrap",
                        action="ENTITY_CREATED",
                        target_type="entity",
                        target_id=entity_id,
                        after={"name": args.entity_name.strip() or domain, "domain": domain},
                    )
                user_id = await create_admin(
                    conn,
                    entity_id=entity_id,
                    email=admin_email,
                    name=args.admin_name.strip() or admin_email,
                    default_profile=args.default_profile.strip() or "default",
                )
                print(f"bootstrap complete: entity={entity_id} admin={user_id}")
            if session_file is not None:
                user_row = await find_active_platform_operator(
                    conn,
                    entity_id=entity_id,
                    email=admin_email,
                )
                if user_row is None:
                    print(
                        "[usage] bootstrap admin is not an active platform operator; cannot issue session",
                        file=sys.stderr,
                    )
                    return 2
                await issue_bootstrap_session(conn, user_row=user_row, session_file=session_file)
                print(f"bootstrap session written: {session_file}")
            return 0
    finally:
        await conn.close()


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
