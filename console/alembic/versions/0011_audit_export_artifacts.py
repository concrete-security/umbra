"""audit export artifacts

Revision ID: 0011_audit_export_artifacts
Revises: 0010_profile_member_added_at
Create Date: 2026-05-16
"""

from alembic import op

revision = "0011_audit_export_artifacts"
down_revision = "0010_profile_member_added_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE audit_export_artifacts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            operation_id UUID NOT NULL UNIQUE REFERENCES operations(id) ON DELETE CASCADE,
            storage_uri TEXT NOT NULL,
            download_token_hash VARCHAR(64) NOT NULL UNIQUE,
            content_type VARCHAR(100) NOT NULL,
            sha256 VARCHAR(64) NOT NULL,
            row_count INT NOT NULL CHECK (row_count >= 0),
            byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
            expires_at TIMESTAMPTZ NOT NULL,
            redeemed_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_audit_export_artifacts_expires_at ON audit_export_artifacts(expires_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_export_artifacts_expires_at")
    op.execute("DROP TABLE IF EXISTS audit_export_artifacts")
