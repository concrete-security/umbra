"""provider drift audit actions

Revision ID: 0013_provider_drift
Revises: 0012_sc_pull_obs
Create Date: 2026-05-16
"""

from alembic import op


revision = "0013_provider_drift"
down_revision = "0012_sc_pull_obs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'CVM_FAILED'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'SECURITY_CVM_STOPPED'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'SECURITY_CVM_FAILED'")


def downgrade() -> None:
    # PostgreSQL cannot drop enum values without recreating the type; keep downgrade a no-op.
    pass
