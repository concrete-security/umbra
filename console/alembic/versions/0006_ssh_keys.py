"""ssh keys

Revision ID: 0006_ssh_keys
Revises: 0005_idempotency_keys
Create Date: 2026-05-15
"""

from alembic import op

revision = "0006_ssh_keys"
down_revision = "0005_idempotency_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE ssh_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            label VARCHAR(200) NOT NULL,
            public_key TEXT NOT NULL,
            fingerprint VARCHAR(128) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_ssh_keys_user_created_at ON ssh_keys(user_id, created_at DESC, id DESC)")
    op.execute("CREATE INDEX ix_ssh_keys_fingerprint ON ssh_keys(fingerprint)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_ssh_keys_fingerprint")
    op.execute("DROP INDEX IF EXISTS ix_ssh_keys_user_created_at")
    op.execute("DROP TABLE IF EXISTS ssh_keys")
