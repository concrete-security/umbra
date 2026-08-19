"""recognize the pre-Umbra managed-secrets lineage

Revision ID: 0030_profile_managed_secrets
Revises: 0029_oauth_connections
Create Date: 2026-08-13

This is a lineage-only compatibility revision. It performs no private feature
DDL on fresh Umbra databases and leaves existing dormant schema and data intact
on migrated databases.
"""


revision = "0030_profile_managed_secrets"
down_revision = "0029_oauth_connections"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
