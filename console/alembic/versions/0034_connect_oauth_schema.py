"""install public Connect / OAuth / managed-secret schema

Revision ID: 0034_connect_oauth_schema
Revises: 0033_public_legacy_merge
Create Date: 2026-08-17

The pre-Umbra compatibility branch left these objects as lineage-only no-ops so
fresh databases would not install a then-removed private feature. Connect is now
a public Umbra surface, so this revision creates the tables and audit actions on
every database that reached ``0033_public_legacy_merge``. Existing Concrete
schema is retained: ``CREATE IF NOT EXISTS`` / ``ADD VALUE IF NOT EXISTS`` keep
a migrated database intact, and ciphertext CHECKs accept Umbra v2 envelopes as
well as legacy v1.
"""

from alembic import op


revision = "0034_connect_oauth_schema"
down_revision = "0033_public_legacy_merge"
branch_labels = None
depends_on = None

_AUDIT_ACTIONS = (
    "PROFILE_SECRET_MINTED",
    "OAUTH_INTEGRATION_CONFIGURED",
    "OAUTH_INTEGRATION_DELETED",
    "PROFILE_CONNECTION_LINK_CREATED",
    "PROFILE_MANAGED_SECRET_CONFIGURED",
    "PROFILE_MANAGED_SECRET_DELETED",
    "PROFILE_SECRET_ROTATED",
    "PROFILE_SECRET_ROTATION_FAILED",
    "CVM_ATTESTATION_UNREACHABLE",
    "SECURITY_CVM_ATTESTATION_UNREACHABLE",
)

_CIPHERTEXT_COLUMNS = (
    ("oauth_integrations", "client_secret_ciphertext"),
    ("profile_managed_secrets", "refresh_token_ciphertext"),
)


def _widen_ciphertext_check(table: str, column: str) -> None:
    op.execute(
        f"""
        ALTER TABLE {table}
        DROP CONSTRAINT IF EXISTS {table}_{column}_check
        """
    )
    op.execute(
        f"""
        ALTER TABLE {table}
        ADD CONSTRAINT {table}_{column}_check
        CHECK ({column} LIKE 'v1:%' OR {column} LIKE 'v2:%')
        """
    )


def upgrade() -> None:
    for action in _AUDIT_ACTIONS:
        op.execute(f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{action}'")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_integrations (
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            name VARCHAR(64) NOT NULL,
            authorize_url TEXT NOT NULL CHECK (authorize_url LIKE 'https://%'),
            token_url TEXT NOT NULL CHECK (token_url LIKE 'https://%'),
            client_id TEXT NOT NULL,
            client_secret_ciphertext TEXT NOT NULL,
            scopes TEXT NOT NULL DEFAULT '',
            token_pointer TEXT NOT NULL,
            profile_policy_template JSONB NULL
                CHECK (
                    profile_policy_template IS NULL
                    OR NOT jsonb_path_exists(profile_policy_template, '$.secret_injections[*].value')
                ),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (entity_id, name)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_connection_states (
            id UUID PRIMARY KEY,
            entity_id UUID NOT NULL,
            integration_name VARCHAR(64) NOT NULL,
            state_token_hash CHAR(64) NOT NULL UNIQUE,
            profile_id UUID NOT NULL REFERENCES entity_profiles(id) ON DELETE CASCADE,
            injection_ids JSONB NOT NULL CHECK (jsonb_typeof(injection_ids) = 'array'),
            created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ NULL,
            completed_at TIMESTAMPTZ NULL,
            error TEXT NULL,
            FOREIGN KEY (entity_id, integration_name)
                REFERENCES oauth_integrations(entity_id, name) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_oauth_connection_states_profile
        ON oauth_connection_states (profile_id, created_at DESC)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_oauth_connection_states_expires_at
        ON oauth_connection_states (expires_at)
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS profile_managed_secrets (
            profile_id UUID NOT NULL REFERENCES entity_profiles(id) ON DELETE CASCADE,
            injection_id VARCHAR(100) NOT NULL,
            provider TEXT NOT NULL DEFAULT 'oauth_refresh_token'
                CHECK (provider = 'oauth_refresh_token'),
            token_url TEXT NOT NULL CHECK (token_url LIKE 'https://%'),
            client_id TEXT NOT NULL,
            refresh_token_ciphertext TEXT NOT NULL,
            account_id TEXT NULL,
            access_token_expires_at TIMESTAMPTZ NULL,
            last_rotated_at TIMESTAMPTZ NULL,
            last_attempt_at TIMESTAMPTZ NULL,
            last_error TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (profile_id, injection_id)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_profile_managed_secrets_due
        ON profile_managed_secrets (access_token_expires_at NULLS FIRST)
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS integration_profiles (
            entity_id UUID NOT NULL,
            integration_name VARCHAR(64) NOT NULL,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            profile_id UUID NOT NULL REFERENCES entity_profiles(id) ON DELETE CASCADE,
            template_sha256 CHAR(64) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (entity_id, integration_name, user_id),
            FOREIGN KEY (entity_id, integration_name)
                REFERENCES oauth_integrations(entity_id, name) ON DELETE CASCADE,
            UNIQUE (profile_id)
        )
        """
    )
    for table, column in _CIPHERTEXT_COLUMNS:
        _widen_ciphertext_check(table, column)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS integration_profiles")
    op.execute("DROP TABLE IF EXISTS profile_managed_secrets")
    op.execute("DROP TABLE IF EXISTS oauth_connection_states")
    op.execute("DROP TABLE IF EXISTS oauth_integrations")
