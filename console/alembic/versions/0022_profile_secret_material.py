"""store profile secret injection material encrypted out-of-policy

Revision ID: 0022_profile_secret_material
Revises: 0021_traffic_logs_attributes
Create Date: 2026-05-28
"""

from alembic import op


revision = "0022_profile_secret_material"
down_revision = "0021_traffic_logs_attributes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE profile_secret_material (
            profile_id UUID NOT NULL REFERENCES entity_profiles(id) ON DELETE CASCADE,
            injection_id VARCHAR(100) NOT NULL,
            ciphertext TEXT NOT NULL CHECK (ciphertext LIKE 'v1:%'),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (profile_id, injection_id)
        )
        """
    )
    op.execute(
        """
        UPDATE entity_profiles
        SET policy = jsonb_set(
            policy,
            '{secret_injections}',
            COALESCE(
                (
                    SELECT jsonb_agg(injection - 'value')
                    FROM jsonb_array_elements(policy -> 'secret_injections') AS injection
                    WHERE jsonb_typeof(injection) = 'object'
                ),
                '[]'::jsonb
            ),
            false
        )
        WHERE jsonb_typeof(policy -> 'secret_injections') = 'array'
        """
    )
    op.execute(
        """
        ALTER TABLE entity_profiles
        ADD CONSTRAINT ck_entity_profiles_policy_no_secret_values
        CHECK (NOT jsonb_path_exists(policy, '$.secret_injections[*].value'))
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE entity_profiles
        DROP CONSTRAINT IF EXISTS ck_entity_profiles_policy_no_secret_values
        """
    )
    op.execute("DROP TABLE IF EXISTS profile_secret_material")
