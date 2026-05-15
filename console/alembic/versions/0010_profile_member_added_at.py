"""add profile membership timestamps

Revision ID: 0010_profile_member_added_at
Revises: 0009_cvm_policy_version
Create Date: 2026-05-15
"""

from alembic import op

revision = "0010_profile_member_added_at"
down_revision = "0009_cvm_policy_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE profile_users ADD COLUMN added_at TIMESTAMPTZ NOT NULL DEFAULT now()")


def downgrade() -> None:
    op.execute("ALTER TABLE profile_users DROP COLUMN IF EXISTS added_at")
