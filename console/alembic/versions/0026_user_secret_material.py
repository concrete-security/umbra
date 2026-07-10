"""store per-user host-bound secret material for profile secret injections

Revision ID: 0026_user_secret_material
Revises: 0025_cvm_disk_size
Create Date: 2026-07-07
"""

from alembic import op


revision = "0026_user_secret_material"
down_revision = "0025_cvm_disk_size"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE user_secret_material (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            ciphertext TEXT NOT NULL CHECK (ciphertext LIKE 'v1:%'),
            allowed_hosts JSONB NOT NULL CHECK (jsonb_typeof(allowed_hosts) = 'array'),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, name)
        )
        """
    )
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'USER_SECRET_SET'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'USER_SECRET_DELETED'")


def downgrade() -> None:
    # PostgreSQL cannot drop enum values in place; the added audit_action
    # values stay behind (same precedent as prior enum-extension migrations).
    op.execute("DROP TABLE IF EXISTS user_secret_material")
