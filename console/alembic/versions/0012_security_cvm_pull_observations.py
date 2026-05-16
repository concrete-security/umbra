"""security cvm pull observations

Revision ID: 0012_sc_pull_obs
Revises: 0011_audit_export_artifacts
Create Date: 2026-05-16
"""

from alembic import op

revision = "0012_sc_pull_obs"
down_revision = "0011_audit_export_artifacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE security_cvms ADD COLUMN last_policy_pull_at TIMESTAMPTZ NULL")
    op.execute("ALTER TABLE security_cvms ADD COLUMN last_policy_pull_etag VARCHAR(80) NULL")
    op.execute(
        """
        ALTER TABLE security_cvms
        ADD COLUMN last_policy_pull_entry_count INT NULL
        CHECK (last_policy_pull_entry_count >= 0)
        """
    )
    op.execute(
        """
        CREATE INDEX ix_security_cvms_last_policy_pull_at
        ON security_cvms(last_policy_pull_at)
        WHERE deleted_at IS NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_security_cvms_last_policy_pull_at")
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS last_policy_pull_entry_count")
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS last_policy_pull_etag")
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS last_policy_pull_at")
