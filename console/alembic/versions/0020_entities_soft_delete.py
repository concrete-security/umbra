"""add entities soft-delete columns

Revision ID: 0020_entities_soft_delete
Revises: 0019_cvm_update_bundles
Create Date: 2026-05-22
"""

from alembic import op

revision = "0020_entities_soft_delete"
down_revision = "0019_cvm_update_bundles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE entities
        ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
        ADD COLUMN IF NOT EXISTS deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE entities DROP COLUMN IF EXISTS deleted_by")
    op.execute("ALTER TABLE entities DROP COLUMN IF EXISTS deleted_at")
