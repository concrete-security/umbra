"""recognize the pre-Umbra profile-secret audit lineage

Revision ID: 0028_profile_secret_mint_audit
Revises: 0027_traffic_logs_decision
Create Date: 2026-08-13

This is a lineage-only compatibility revision. Databases migrated by the
pre-Umbra Console already contain its schema effects; fresh Umbra databases
must not install the removed private feature. Existing dormant schema and data
are intentionally retained.
"""


revision = "0028_profile_secret_mint_audit"
down_revision = "0027_traffic_logs_decision"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
