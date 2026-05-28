"""Add Dev CVM control-plane bearer purpose.

Revision ID: 0023_dev_cvm_control_tokens
Revises: 0022_profile_secret_material
"""

from typing import Union

from alembic import op

revision = "0023_dev_cvm_control_tokens"
down_revision: Union[str, None] = "0022_profile_secret_material"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE service_principal_token_purpose ADD VALUE IF NOT EXISTS 'DEV_CONTROL'")
    op.execute(
        """
        DO $$
        DECLARE
            constraint_name text;
        BEGIN
            SELECT conname INTO constraint_name
            FROM pg_constraint
            WHERE conrelid = 'service_principal_tokens'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%PROXY_AUTH%';
            IF constraint_name IS NOT NULL THEN
                EXECUTE format('ALTER TABLE service_principal_tokens DROP CONSTRAINT %I', constraint_name);
            END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        ALTER TABLE service_principal_tokens
        ADD CONSTRAINT ck_service_principal_tokens_principal_purpose
        CHECK (
            (principal_type = 'security_cvm' AND purpose IN ('INGEST', 'CA_EXPORT'))
            OR (principal_type = 'dev_cvm' AND purpose IN ('PROXY_AUTH', 'DEV_CONTROL'))
        )
        """
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE service_principal_tokens DROP CONSTRAINT IF EXISTS ck_service_principal_tokens_principal_purpose"
    )
    op.execute(
        """
        ALTER TABLE service_principal_tokens
        ADD CONSTRAINT ck_service_principal_tokens_principal_purpose
        CHECK (
            (principal_type = 'security_cvm' AND purpose IN ('INGEST', 'CA_EXPORT'))
            OR (principal_type = 'dev_cvm' AND purpose = 'PROXY_AUTH')
        )
        """
    )
