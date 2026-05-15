"""quota tables

Revision ID: 0004_quota_tables
Revises: 0003_auth_flow_tables
Create Date: 2026-05-15
"""

from alembic import op

revision = "0004_quota_tables"
down_revision = "0003_auth_flow_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TYPE quota_resource AS ENUM (
            'dev_cvms',
            'ssh_keys',
            'users',
            'profiles'
        )
        """
    )
    op.execute(
        """
        CREATE TABLE entity_quotas (
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            resource quota_resource NOT NULL,
            limit_value INT NOT NULL CHECK (limit_value >= 0),
            set_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            set_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (entity_id, resource)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE user_quotas (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            resource quota_resource NOT NULL,
            limit_value INT NOT NULL CHECK (limit_value >= 0),
            set_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            set_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, resource),
            CHECK (resource IN ('dev_cvms', 'ssh_keys'))
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_quotas")
    op.execute("DROP TABLE IF EXISTS entity_quotas")
    op.execute("DROP TYPE IF EXISTS quota_resource")
