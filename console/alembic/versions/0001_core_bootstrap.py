"""core bootstrap tables

Revision ID: 0001_core_bootstrap
Revises:
Create Date: 2026-05-15
"""

from alembic import op

revision = "0001_core_bootstrap"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        CREATE TYPE permission AS ENUM (
            'CVM_LAUNCH',
            'CVM_MANAGE',
            'SECURITY_CVM_CONFIGURE',
            'TRAFFIC_LOGS_VIEW',
            'AUDIT_VIEW',
            'AUDIT_EXPORT',
            'USER_MANAGE',
            'PERMISSION_MANAGE',
            'QUOTA_MANAGE',
            'PLATFORM_OPERATOR'
        )
        """
    )
    op.execute(
        """
        CREATE TABLE entities (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(200) NOT NULL,
            domain VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(320) NOT NULL,
            name VARCHAR(200) NOT NULL DEFAULT '',
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deactivated_at TIMESTAMPTZ NULL,
            deactivated_by UUID NULL,
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL
        )
        """
    )
    op.execute("CREATE UNIQUE INDEX ux_users_email_live ON users(email) WHERE deleted_at IS NULL")
    op.execute(
        """
        CREATE TABLE user_permissions (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission permission NOT NULL,
            PRIMARY KEY (user_id, permission)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE entity_profiles (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            name VARCHAR(200) NOT NULL,
            description VARCHAR(1000) NOT NULL DEFAULT '',
            policy JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_entity_profiles_entity_name_live
        ON entity_profiles(entity_id, name)
        WHERE deleted_at IS NULL
        """
    )
    op.execute(
        """
        CREATE TABLE audit_events (
            seq BIGSERIAL UNIQUE NOT NULL,
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_id UUID NULL REFERENCES entities(id) ON DELETE SET NULL,
            actor_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            actor_email VARCHAR(320) NOT NULL,
            action VARCHAR(100) NOT NULL,
            target_type VARCHAR(50) NULL,
            target_id UUID NULL,
            before JSONB NOT NULL DEFAULT '{}'::jsonb,
            after JSONB NOT NULL DEFAULT '{}'::jsonb,
            request_id VARCHAR(128) NULL,
            ip_address VARCHAR(45) NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            prev_hash CHAR(64) NOT NULL,
            row_hash CHAR(64) NOT NULL UNIQUE
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_events")
    op.execute("DROP INDEX IF EXISTS ux_entity_profiles_entity_name_live")
    op.execute("DROP TABLE IF EXISTS entity_profiles")
    op.execute("DROP TABLE IF EXISTS user_permissions")
    op.execute("DROP INDEX IF EXISTS ux_users_email_live")
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP TABLE IF EXISTS entities")
    op.execute("DROP TYPE IF EXISTS permission")
