"""security cvm ingest plaintext stash

Revision ID: 0014_sc_ingest_stash
Revises: 0013_provider_drift
Create Date: 2026-05-16
"""

from alembic import op


revision = "0014_sc_ingest_stash"
down_revision = "0013_provider_drift"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE security_cvms ADD COLUMN ingest_token_plaintext VARCHAR(128) NULL")
    op.execute("ALTER TABLE security_cvms ADD COLUMN ingest_token_stashed_at TIMESTAMPTZ NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS ingest_token_stashed_at")
    op.execute("ALTER TABLE security_cvms DROP COLUMN IF EXISTS ingest_token_plaintext")
