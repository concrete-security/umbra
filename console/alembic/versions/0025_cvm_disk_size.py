"""Add cvms.disk_size_gb and widen user_quotas disk resources.

Revision ID: 0025_cvm_disk_size
Revises: 0024_disk_quota_resources
"""

from typing import Union

from alembic import op

revision = "0025_cvm_disk_size"
down_revision: Union[str, None] = "0024_disk_quota_resources"
branch_labels = None
depends_on = None

# Matches DEV_CVM_DEFAULT_DISK_GB and Phala's own 40GB deploy default: every CVM
# launched before this column existed was provisioned at that size, so backfill
# to it keeps disk_gb_total sums consistent.
DEFAULT_DISK_GB = 40


def upgrade() -> None:
    # user_quotas restricted resources to dev_cvms/ssh_keys via an unnamed inline
    # CHECK (migration 0004); widen it to also allow the two per-user disk quotas.
    op.execute(
        """
        DO $$
        DECLARE
            constraint_name text;
        BEGIN
            SELECT conname INTO constraint_name
            FROM pg_constraint
            WHERE conrelid = 'user_quotas'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%dev_cvms%';
            IF constraint_name IS NOT NULL THEN
                EXECUTE format('ALTER TABLE user_quotas DROP CONSTRAINT %I', constraint_name);
            END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        ALTER TABLE user_quotas
        ADD CONSTRAINT ck_user_quotas_resource
        CHECK (resource IN ('dev_cvms', 'ssh_keys', 'disk_gb_per_cvm', 'disk_gb_total'))
        """
    )
    op.execute("ALTER TABLE cvms ADD COLUMN disk_size_gb INT NULL")
    op.execute(f"UPDATE cvms SET disk_size_gb = {DEFAULT_DISK_GB} WHERE disk_size_gb IS NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE cvms DROP COLUMN IF EXISTS disk_size_gb")
    # Drop any disk quota rows before restoring the narrower CHECK, or the
    # re-add would fail against existing disk_gb_* rows.
    op.execute("DELETE FROM user_quotas WHERE resource IN ('disk_gb_per_cvm', 'disk_gb_total')")
    op.execute("ALTER TABLE user_quotas DROP CONSTRAINT IF EXISTS ck_user_quotas_resource")
    op.execute(
        """
        ALTER TABLE user_quotas
        ADD CONSTRAINT user_quotas_resource_check
        CHECK (resource IN ('dev_cvms', 'ssh_keys'))
        """
    )
