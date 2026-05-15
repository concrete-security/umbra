from __future__ import annotations

from uuid import UUID

import asyncpg

from concrete_console.audit import insert_audit_event
from concrete_console.bootstrap import email_domain
from concrete_console.errors import api_error

UNAUTHORIZED_ACCOUNT_MESSAGE = "Account is not authorized for this Console"


def oidc_forbidden():
    return api_error(403, "FORBIDDEN", UNAUTHORIZED_ACCOUNT_MESSAGE)


async def resolve_oidc_user(
    conn: asyncpg.Connection,
    *,
    provider: str,
    claims: dict,
) -> UUID:
    email = str(claims["email"]).strip().lower()
    subject = str(claims["sub"])
    identity = await conn.fetchrow(
        """
        SELECT user_id
        FROM oauth_identities
        WHERE provider = $1
          AND provider_subject_id = $2
          AND deleted_at IS NULL
        """,
        provider,
        subject,
    )
    if identity is not None:
        user = await _fetch_active_user(conn, identity["user_id"])
        await conn.execute(
            """
            UPDATE oauth_identities
            SET email = $3,
                last_login_at = now()
            WHERE provider = $1
              AND provider_subject_id = $2
              AND deleted_at IS NULL
            """,
            provider,
            subject,
            email,
        )
        return user["id"]

    try:
        domain = email_domain(email)
    except ValueError:
        raise oidc_forbidden() from None

    user = await conn.fetchrow(
        """
        SELECT u.id, u.email, u.entity_id, u.deactivated_at, u.deleted_at, e.domain
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        WHERE u.email = $1
          AND u.deleted_at IS NULL
        """,
        email,
    )
    if user is None or user["domain"] != domain or user["deactivated_at"] is not None:
        raise oidc_forbidden()

    existing_for_user = await conn.fetchrow(
        """
        SELECT provider_subject_id
        FROM oauth_identities
        WHERE user_id = $1
          AND provider = $2
          AND deleted_at IS NULL
        """,
        user["id"],
        provider,
    )
    if existing_for_user is not None and existing_for_user["provider_subject_id"] != subject:
        await insert_audit_event(
            conn,
            entity_id=user["entity_id"],
            actor_id=user["id"],
            actor_email=user["email"],
            action="OAUTH_REBIND_REFUSED",
            target_type="user",
            target_id=user["id"],
            after={"provider": provider},
        )
        raise oidc_forbidden()

    await conn.execute(
        """
        INSERT INTO oauth_identities (
            user_id,
            provider,
            provider_subject_id,
            email,
            last_login_at
        )
        VALUES ($1, $2, $3, $4, now())
        """,
        user["id"],
        provider,
        subject,
        email,
    )
    await insert_audit_event(
        conn,
        entity_id=user["entity_id"],
        actor_id=user["id"],
        actor_email=user["email"],
        action="OAUTH_IDENTITY_LINKED",
        target_type="user",
        target_id=user["id"],
        after={"provider": provider},
    )
    return user["id"]


async def _fetch_active_user(conn: asyncpg.Connection, user_id: UUID) -> asyncpg.Record:
    user = await conn.fetchrow(
        """
        SELECT id, email, entity_id
        FROM users
        WHERE id = $1
          AND deactivated_at IS NULL
          AND deleted_at IS NULL
        """,
        user_id,
    )
    if user is None:
        raise oidc_forbidden()
    return user
