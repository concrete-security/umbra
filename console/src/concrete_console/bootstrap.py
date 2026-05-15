from __future__ import annotations

import argparse
import asyncio
import os
import sys
from uuid import UUID, uuid4

import asyncpg

from concrete_console.audit import insert_audit_event
from concrete_console.config import asyncpg_dsn, load_settings

BOOTSTRAP_PERMISSIONS = (
    "PLATFORM_OPERATOR",
    "USER_MANAGE",
    "PERMISSION_MANAGE",
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
    return parser.parse_args()


async def ensure_entity(conn: asyncpg.Connection, *, name: str, domain: str) -> UUID:
    entity_id = await conn.fetchval("SELECT id FROM entities WHERE domain = $1", domain)
    if entity_id:
        return entity_id

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
    return entity_id


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
    return user_id


async def run() -> int:
    if os.environ.get("CONCRETE_ALLOW_BOOTSTRAP") != "true":
        print("[usage] set CONCRETE_ALLOW_BOOTSTRAP=true to run bootstrap", file=sys.stderr)
        return 2

    args = parse_args()
    domain = args.domain.strip().lower()
    admin_email = args.admin_email.strip().lower()
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
            entity_id = await ensure_entity(
                conn,
                name=args.entity_name.strip() or domain,
                domain=domain,
            )
            if await has_permission_manager(conn, entity_id):
                print("bootstrap already complete")
                return 0
            user_id = await create_admin(
                conn,
                entity_id=entity_id,
                email=admin_email,
                name=args.admin_name.strip() or admin_email,
                default_profile=args.default_profile.strip() or "default",
            )
            print(f"bootstrap complete: entity={entity_id} admin={user_id}")
            return 0
    finally:
        await conn.close()


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
