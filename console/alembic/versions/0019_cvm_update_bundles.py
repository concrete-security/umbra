"""add cvm update policy bundles

Revision ID: 0019_cvm_update_bundles
Revises: 0018_audit_anchors_redaction_seq
Create Date: 2026-05-19
"""

from alembic import op

revision = "0019_cvm_update_bundles"
down_revision = "0018_audit_anchors_redaction_seq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'CVM_UPDATED'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'SECURITY_CVM_UPDATED'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'CVM_UPDATE_FAILED'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'SECURITY_CVM_UPDATE_FAILED'")
    op.execute("ALTER TABLE cvms ADD COLUMN atls_policy_bundle JSONB NULL")
    op.execute("ALTER TABLE cvms ADD COLUMN atls_policy_revision BIGINT NOT NULL DEFAULT 0")
    op.execute(
        """
        UPDATE cvms
        SET atls_policy_bundle = metadata -> 'policy_bundle',
            atls_policy_revision = 1
        WHERE atls_policy_bundle IS NULL
          AND jsonb_typeof(metadata -> 'policy_bundle') = 'object'
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE cvms DROP COLUMN IF EXISTS atls_policy_revision")
    op.execute("ALTER TABLE cvms DROP COLUMN IF EXISTS atls_policy_bundle")
    # PostgreSQL cannot drop enum values without recreating the type; keep downgrade a no-op for audit values.
