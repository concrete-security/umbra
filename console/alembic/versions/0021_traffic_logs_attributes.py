"""add traffic_logs.attributes for SC body-assertion extraction

Revision ID: 0021_traffic_logs_attributes
Revises: 0020_entities_soft_delete
Create Date: 2026-05-28
"""

from alembic import op


revision = "0021_traffic_logs_attributes"
down_revision = "0020_entities_soft_delete"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE traffic_logs
        ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}'::jsonb
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE traffic_logs DROP COLUMN IF EXISTS attributes")
