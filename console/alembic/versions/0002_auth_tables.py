"""auth tables

Revision ID: 0002_auth_tables
Revises: 0001_core_bootstrap
Create Date: 2026-05-15
"""

from alembic import op

revision = "0002_auth_tables"
down_revision = "0001_core_bootstrap"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE revoked_tokens (
            jti UUID PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            revoked_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_revoked_tokens_expires_at ON revoked_tokens(expires_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_revoked_tokens_expires_at")
    op.execute("DROP TABLE IF EXISTS revoked_tokens")
