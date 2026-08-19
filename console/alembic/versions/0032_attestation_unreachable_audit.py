"""recognize the deployed pre-Umbra database head

Revision ID: 0032_attn_unreachable
Revises: 0031_connect_profiles
Create Date: 2026-08-13

This is a lineage-only compatibility revision. It performs no private feature
DDL on fresh Umbra databases and leaves existing dormant schema and data intact
on migrated databases.
"""


revision = "0032_attn_unreachable"
down_revision = "0031_connect_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
