"""operations table

Revision ID: 0007_operations
Revises: 0006_ssh_keys
Create Date: 2026-05-15
"""

from alembic import op

revision = "0007_operations"
down_revision = "0006_ssh_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TYPE operation_status AS ENUM (
            'pending',
            'running',
            'succeeded',
            'failed',
            'cancelled'
        )
        """
    )
    op.execute(
        """
        CREATE TABLE operations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            kind VARCHAR(64) NOT NULL,
            status operation_status NOT NULL DEFAULT 'pending',
            actor_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            actor_email VARCHAR(320) NULL,
            target_type VARCHAR(50) NULL,
            target_id UUID NULL,
            idempotency_key VARCHAR(128) NULL,
            request_body_sha256 VARCHAR(64) NULL,
            progress_step VARCHAR(64) NULL,
            progress_percent INT NULL CHECK (progress_percent BETWEEN 0 AND 100),
            result JSONB NULL,
            result_disclosed_at TIMESTAMPTZ NULL,
            error JSONB NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_operations_actor_created_at ON operations(actor_id, created_at DESC)")
    op.execute(
        """
        CREATE INDEX ix_operations_active
        ON operations(created_at)
        WHERE status IN ('pending', 'running')
        """
    )
    op.execute("CREATE INDEX ix_operations_expires_at ON operations(expires_at) WHERE expires_at IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_operations_expires_at")
    op.execute("DROP INDEX IF EXISTS ix_operations_active")
    op.execute("DROP INDEX IF EXISTS ix_operations_actor_created_at")
    op.execute("DROP TABLE IF EXISTS operations")
    op.execute("DROP TYPE IF EXISTS operation_status")
