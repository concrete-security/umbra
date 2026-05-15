"""idempotency keys

Revision ID: 0005_idempotency_keys
Revises: 0004_quota_tables
Create Date: 2026-05-15
"""

from alembic import op

revision = "0005_idempotency_keys"
down_revision = "0004_quota_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE idempotency_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            credential_id VARCHAR(128) NOT NULL,
            idempotency_key VARCHAR(128) NOT NULL,
            route VARCHAR(255) NOT NULL,
            request_body_sha256 VARCHAR(64) NOT NULL,
            response_status INT NOT NULL,
            response_body JSONB NULL,
            response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours')
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_idempotency_keys_scope
        ON idempotency_keys(credential_id, idempotency_key, route)
        """
    )
    op.execute("CREATE INDEX ix_idempotency_keys_expires_at ON idempotency_keys(expires_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_idempotency_keys_expires_at")
    op.execute("DROP INDEX IF EXISTS ux_idempotency_keys_scope")
    op.execute("DROP TABLE IF EXISTS idempotency_keys")
