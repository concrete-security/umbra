"""add cvm policy version

Revision ID: 0009_cvm_policy_version
Revises: 0008_cvm_traffic_tables
Create Date: 2026-05-15
"""

from alembic import op

revision = "0009_cvm_policy_version"
down_revision = "0008_cvm_traffic_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cvms ADD COLUMN policy_version BIGINT NOT NULL DEFAULT 0")


def downgrade() -> None:
    op.execute("ALTER TABLE cvms DROP COLUMN IF EXISTS policy_version")
