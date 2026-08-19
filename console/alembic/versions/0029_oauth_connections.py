"""recognize the pre-Umbra OAuth-connections lineage

Revision ID: 0029_oauth_connections
Revises: 0028_profile_secret_mint_audit
Create Date: 2026-08-13

This is a lineage-only compatibility revision. It lets Alembic recognize a
durable pre-Umbra database without installing the removed private feature on a
fresh Umbra database. Existing dormant schema and data are retained.
"""


revision = "0029_oauth_connections"
down_revision = "0028_profile_secret_mint_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
