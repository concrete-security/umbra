"""Add disk-size quota resources.

Revision ID: 0024_disk_quota_resources
Revises: 0023_dev_cvm_control_tokens
"""

from typing import Union

from alembic import op

revision = "0024_disk_quota_resources"
down_revision: Union[str, None] = "0023_dev_cvm_control_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New enum values must be added in a migration that does not also *use* them
    # (a value cannot be referenced in the same transaction that adds it), so the
    # user_quotas CHECK that consumes these lives in the following migration.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE quota_resource ADD VALUE IF NOT EXISTS 'disk_gb_per_cvm'")
        op.execute("ALTER TYPE quota_resource ADD VALUE IF NOT EXISTS 'disk_gb_total'")


def downgrade() -> None:
    # Postgres cannot drop enum values without recreating the type; leave the
    # added values in place (harmless when unused), mirroring 0023's downgrade.
    pass
