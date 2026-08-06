import asyncio
from uuid import UUID, uuid4

import asyncpg
import pytest
from fastapi import HTTPException

from umbra_console.account_resolution import (
    UNAUTHORIZED_ACCOUNT_MESSAGE,
    oidc_display_name,
    resolve_oidc_user,
)


class AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return None


class AccountResolutionDb:
    def __init__(self) -> None:
        self.entities: dict[str, dict] = {}
        self.users: dict[str, dict] = {}
        self.oauth: dict[tuple[str, str], dict] = {}
        self.audit_events: list[dict] = []
        self.user_count_by_entity: dict[UUID, int] = {}
        self.quota_limits: dict[tuple[UUID, str], int] = {}
        self.insert_users_attempts = 0

    def add_entity(self, *, domain: str, entity_id: UUID | None = None) -> UUID:
        entity_id = entity_id or uuid4()
        self.entities[domain] = {"id": entity_id, "domain": domain}
        self.user_count_by_entity.setdefault(entity_id, 0)
        return entity_id

    def add_user(
        self,
        *,
        email: str,
        entity_id: UUID,
        domain: str,
        deactivated: bool = False,
        user_id: UUID | None = None,
    ) -> UUID:
        user_id = user_id or uuid4()
        self.users[email] = {
            "id": user_id,
            "email": email,
            "entity_id": entity_id,
            "domain": domain,
            "deactivated_at": object() if deactivated else None,
            "name": email.split("@", 1)[0],
        }
        self.user_count_by_entity[entity_id] = self.user_count_by_entity.get(entity_id, 0) + 1
        return user_id

    def add_oauth(self, *, provider: str, subject: str, user_id: UUID, email: str) -> None:
        self.oauth[(provider, subject)] = {"user_id": user_id, "email": email}

    def set_users_quota(self, entity_id: UUID, limit: int) -> None:
        self.quota_limits[(entity_id, "users")] = limit

    def conn(self) -> "AccountResolutionConn":
        return AccountResolutionConn(self)


class AccountResolutionConn:
    def __init__(self, db: AccountResolutionDb) -> None:
        self.db = db

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query: str, *args):
        normalized = " ".join(query.split()).lower()
        if "from oauth_identities" in normalized and "provider_subject_id" in normalized:
            provider, subject = args[0], args[1]
            row = self.db.oauth.get((provider, subject))
            return {"user_id": row["user_id"]} if row else None
        if "from entities" in normalized and "where domain" in normalized:
            domain = args[0]
            entity = self.db.entities.get(domain)
            return dict(entity) if entity else None
        if "from users u" in normalized and "where u.email" in normalized:
            email = args[0]
            user = self.db.users.get(email)
            if user is None:
                return None
            return {
                "id": user["id"],
                "email": user["email"],
                "entity_id": user["entity_id"],
                "deactivated_at": user["deactivated_at"],
                "domain": user["domain"],
            }
        if "from users" in normalized and "where id = $1" in normalized:
            user_id = args[0]
            for user in self.db.users.values():
                if user["id"] == user_id and user["deactivated_at"] is None:
                    return {"id": user["id"], "email": user["email"], "entity_id": user["entity_id"]}
            return None
        if "from oauth_identities" in normalized and "where user_id" in normalized:
            user_id, provider = args[0], args[1]
            for (prov, sub), row in self.db.oauth.items():
                if prov == provider and row["user_id"] == user_id:
                    return {"provider_subject_id": sub}
            return None
        if "from entity_quotas" in normalized:
            entity_id, resource = args[0], args[1]
            limit = self.db.quota_limits.get((entity_id, resource))
            if limit is None:
                return None
            return {"limit_value": limit, "set_by": None, "set_at": None}
        raise AssertionError(f"unexpected fetchrow query: {query}")

    async def fetchval(self, query: str, *args):
        normalized = " ".join(query.split()).lower()
        if "select count(*) from users where entity_id" in normalized:
            entity_id = args[0]
            return self.db.user_count_by_entity.get(entity_id, 0)
        raise AssertionError(f"unexpected fetchval query: {query}")

    async def execute(self, query: str, *args):
        normalized = " ".join(query.split()).lower()
        if "update oauth_identities" in normalized:
            return "UPDATE 1"
        if "insert into oauth_identities" in normalized:
            user_id, provider, subject, email = args[0], args[1], args[2], args[3]
            self.db.oauth[(provider, subject)] = {"user_id": user_id, "email": email}
            return "INSERT 1"
        if "insert into users" in normalized:
            self.db.insert_users_attempts += 1
            user_id, email, name, entity_id = args[0], args[1], args[2], args[3]
            domain = next(entity["domain"] for entity in self.db.entities.values() if entity["id"] == entity_id)
            self.db.add_user(email=email, entity_id=entity_id, domain=domain, user_id=user_id)
            self.db.users[email]["name"] = name
            return "INSERT 1"
        raise AssertionError(f"unexpected execute query: {query}")


@pytest.fixture(autouse=True)
def patch_audit_insert(monkeypatch):
    async def fake_insert_audit(conn, **kwargs):
        if isinstance(conn, AccountResolutionConn):
            conn.db.audit_events.append(kwargs)

    monkeypatch.setattr("umbra_console.account_resolution.insert_audit_event", fake_insert_audit)


async def _noop_entity_quota(conn, entity_id, resource) -> None:
    return None


async def _resolve(db: AccountResolutionDb, *, email: str, sub: str = "google-sub", name: str | None = None) -> UUID:
    claims = {"email": email, "sub": sub}
    if name is not None:
        claims["name"] = name
    return await resolve_oidc_user(db.conn(), provider="google", claims=claims)


def _forbidden(exc: HTTPException) -> bool:
    return (
        exc.status_code == 403
        and exc.detail["error"]["code"] == "FORBIDDEN"
        and exc.detail["error"]["message"] == UNAUTHORIZED_ACCOUNT_MESSAGE
        and exc.detail["error"]["details"] == {}
    )


def test_oidc_display_name_prefers_claim() -> None:
    assert oidc_display_name({"name": "Jane Doe"}, "jane@example.com") == "Jane Doe"


def test_oidc_display_name_falls_back_to_local_part() -> None:
    assert oidc_display_name({}, "jane.doe@example.com") == "jane.doe"


def test_unknown_domain_is_forbidden() -> None:
    db = AccountResolutionDb()

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(_resolve(db, email="user@unknown.example"))

    assert _forbidden(excinfo.value)


def test_jit_provisions_user_and_links_oauth(monkeypatch) -> None:
    db = AccountResolutionDb()
    entity_id = db.add_entity(domain="example.com")
    monkeypatch.setattr("umbra_console.account_resolution.enforce_entity_quota", _noop_entity_quota)

    user_id = asyncio.run(
        _resolve(db, email="dev@example.com", sub="sub-1", name="Dev User")
    )

    assert user_id in {user["id"] for user in db.users.values()}
    user = db.users["dev@example.com"]
    assert user["entity_id"] == entity_id
    assert user["name"] == "Dev User"
    assert ("google", "sub-1") in db.oauth
    assert any(event["action"] == "USER_REGISTERED" for event in db.audit_events)


def test_deactivated_user_is_forbidden(monkeypatch) -> None:
    db = AccountResolutionDb()
    entity_id = db.add_entity(domain="example.com")
    db.add_user(
        email="dev@example.com",
        entity_id=entity_id,
        domain="example.com",
        deactivated=True,
    )
    monkeypatch.setattr("umbra_console.account_resolution.enforce_entity_quota", _noop_entity_quota)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(_resolve(db, email="dev@example.com"))

    assert _forbidden(excinfo.value)


def test_existing_oauth_link_does_not_insert_user(monkeypatch) -> None:
    db = AccountResolutionDb()
    entity_id = db.add_entity(domain="example.com")
    user_id = db.add_user(
        email="dev@example.com", entity_id=entity_id, domain="example.com"
    )
    db.add_oauth(
        provider="google", subject="sub-1", user_id=user_id, email="dev@example.com"
    )
    monkeypatch.setattr("umbra_console.account_resolution.enforce_entity_quota", _noop_entity_quota)

    resolved = asyncio.run(_resolve(db, email="dev@example.com", sub="sub-1"))

    assert resolved == user_id
    assert db.insert_users_attempts == 0


def test_users_quota_exhaustion_is_uniform_forbidden(monkeypatch) -> None:
    db = AccountResolutionDb()
    entity_id = db.add_entity(domain="example.com")
    db.set_users_quota(entity_id, 0)

    async def raise_quota(conn, eid, resource):
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "QUOTA_EXCEEDED",
                    "message": "entity quota exceeded",
                    "details": {"resource": resource, "scope": "entity", "limit": 0, "current_usage": 0},
                }
            },
        )

    monkeypatch.setattr("umbra_console.account_resolution.enforce_entity_quota", raise_quota)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(_resolve(db, email="new@example.com"))

    assert _forbidden(excinfo.value)


def test_concurrent_jit_recovers_from_unique_violation(monkeypatch) -> None:
    db = AccountResolutionDb()
    entity_id = db.add_entity(domain="example.com")
    monkeypatch.setattr("umbra_console.account_resolution.enforce_entity_quota", _noop_entity_quota)

    async def run() -> UUID:
        conn = db.conn()
        original_execute = conn.execute

        async def execute_with_race(query, *args):
            normalized = " ".join(query.split()).lower()
            if "insert into users" in normalized:
                db.add_user(
                    email=args[1],
                    entity_id=args[3],
                    domain="example.com",
                    user_id=args[0],
                )
                raise asyncpg.UniqueViolationError("duplicate email")
            return await original_execute(query, *args)

        conn.execute = execute_with_race
        return await resolve_oidc_user(
            conn,
            provider="google",
            claims={"email": "dev@example.com", "sub": "sub-race"},
        )

    user_id = asyncio.run(run())

    assert db.users["dev@example.com"]["id"] == user_id
    assert ("google", "sub-race") in db.oauth
