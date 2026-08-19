"""recognize the pre-Umbra connect-profiles lineage

Revision ID: 0031_connect_profiles
Revises: 0030_profile_managed_secrets
Create Date: 2026-08-13

This is a lineage-only compatibility revision. It performs no private feature
DDL on fresh Umbra databases and leaves existing dormant schema and data intact
on migrated databases.
"""


revision = "0031_connect_profiles"
down_revision = "0030_profile_managed_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
