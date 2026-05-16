"""audit export scheduler requests

Revision ID: 0015_audit_export_requests
Revises: 0014_sc_ingest_stash
Create Date: 2026-05-16
"""

from alembic import op

revision = "0015_audit_export_requests"
down_revision = "0014_sc_ingest_stash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE audit_export_requests (
            operation_id UUID PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            filters JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_audit_export_requests_entity ON audit_export_requests(entity_id, created_at DESC)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_export_requests_entity")
    op.execute("DROP TABLE IF EXISTS audit_export_requests")
