from __future__ import annotations

from uuid import UUID, uuid4

import asyncpg
from fastapi import HTTPException

from umbra_console.audit import insert_audit_event
from umbra_console.bootstrap import email_domain
from umbra_console.errors import api_error
from umbra_console.routes import enforce_entity_quota

UNAUTHORIZED_ACCOUNT_MESSAGE = "Account is not authorized for this Console"


def oidc_forbidden():
    return api_error(403, "FORBIDDEN", UNAUTHORIZED_ACCOUNT_MESSAGE)


def oidc_display_name(claims: dict, email: str) -> str:
    name = claims.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()[:200]
    return email.split("@", 1)[0]


def _quota_exceeded(exc: HTTPException) -> bool:
    detail = exc.detail
    if not isinstance(detail, dict):
        return False
    error = detail.get("error")
    if not isinstance(error, dict):
        return False
    return error.get("code") == "QUOTA_EXCEEDED"


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

    entity = await conn.fetchrow(
        """
        SELECT id, domain
        FROM entities
        WHERE domain = $1
          AND deleted_at IS NULL
        """,
        domain,
    )
    if entity is None:
        raise oidc_forbidden()

    user = await _fetch_user_by_email(conn, email)
    if user is None:
        user = await _materialize_user(
            conn,
            entity_id=entity["id"],
            entity_domain=entity["domain"],
            email=email,
            claims=claims,
        )
    elif user["domain"] != domain or user["deactivated_at"] is not None:
        raise oidc_forbidden()
    elif user["entity_id"] != entity["id"]:
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


async def _materialize_user(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID,
    entity_domain: str,
    email: str,
    claims: dict,
) -> asyncpg.Record:
    try:
        await enforce_entity_quota(conn, entity_id, "users")
    except HTTPException as exc:
        if _quota_exceeded(exc):
            raise oidc_forbidden() from None
        raise

    user_id = uuid4()
    display_name = oidc_display_name(claims, email)
    try:
        await conn.execute(
            """
            INSERT INTO users (id, email, name, entity_id)
            VALUES ($1, $2, $3, $4)
            """,
            user_id,
            email,
            display_name,
            entity_id,
        )
    except asyncpg.UniqueViolationError:
        user = await _fetch_user_by_email(conn, email)
        if user is None or user["domain"] != entity_domain or user["deactivated_at"] is not None:
            raise oidc_forbidden() from None
        return user

    await insert_audit_event(
        conn,
        entity_id=entity_id,
        actor_id=user_id,
        actor_email=email,
        action="USER_REGISTERED",
        target_type="user",
        target_id=user_id,
        after={"email": email, "name": display_name, "entity_id": str(entity_id)},
    )
    user = await _fetch_user_by_email(conn, email)
    if user is None:
        raise oidc_forbidden()
    return user


async def _fetch_user_by_email(conn: asyncpg.Connection, email: str) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT u.id, u.email, u.entity_id, u.deactivated_at, e.domain
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        WHERE u.email = $1
          AND u.deleted_at IS NULL
        """,
        email,
    )


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
