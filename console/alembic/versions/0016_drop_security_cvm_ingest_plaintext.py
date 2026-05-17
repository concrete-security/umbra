"""drop security cvm ingest plaintext stash

Revision ID: 0016_drop_sc_ingest_plaintext
Revises: 0015_audit_export_requests
Create Date: 2026-05-16
"""

from alembic import op


revision = "0016_drop_sc_ingest_plaintext"
down_revision = "0015_audit_export_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS ingest_token_stashed_at")
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS ingest_token_plaintext")


def downgrade() -> None:
    op.execute("ALTER TABLE security_cvms ADD COLUMN ingest_token_plaintext VARCHAR(128) NULL")
    op.execute("ALTER TABLE security_cvms ADD COLUMN ingest_token_stashed_at TIMESTAMPTZ NULL")
