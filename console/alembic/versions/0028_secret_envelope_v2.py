"""accept Umbra v2 secret-material envelopes

Revision ID: 0028_secret_envelope_v2
Revises: 0027_traffic_logs_decision
Create Date: 2026-08-04
"""

from alembic import op


revision = "0028_secret_envelope_v2"
down_revision = "0027_traffic_logs_decision"
branch_labels = None
depends_on = None


_TABLES = ("profile_secret_material", "user_secret_material")


def upgrade() -> None:
    for table in _TABLES:
        op.execute(
            f"""
            ALTER TABLE {table}
            DROP CONSTRAINT IF EXISTS {table}_ciphertext_check
            """
        )
        op.execute(
            f"""
            ALTER TABLE {table}
            ADD CONSTRAINT {table}_ciphertext_check
            CHECK (ciphertext LIKE 'v1:%' OR ciphertext LIKE 'v2:%')
            """
        )


def downgrade() -> None:
    for table in _TABLES:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM {table} WHERE ciphertext LIKE 'v2:%') THEN
                    RAISE EXCEPTION
                        'cannot downgrade secret envelopes while {table} contains v2 rows';
                END IF;
            END
            $$
            """
        )

    for table in _TABLES:
        op.execute(
            f"""
            ALTER TABLE {table}
            DROP CONSTRAINT IF EXISTS {table}_ciphertext_check
            """
        )
        op.execute(
            f"""
            ALTER TABLE {table}
            ADD CONSTRAINT {table}_ciphertext_check
            CHECK (ciphertext LIKE 'v1:%')
            """
        )
