"""auth flow tables

Revision ID: 0003_auth_flow_tables
Revises: 0002_auth_tables
Create Date: 2026-05-15
"""

from alembic import op

revision = "0003_auth_flow_tables"
down_revision = "0002_auth_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE oauth_identities (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider VARCHAR(50) NOT NULL,
            provider_subject_id VARCHAR(255) NOT NULL,
            email VARCHAR(320) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_login_at TIMESTAMPTZ NULL,
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_oauth_identities_provider_subject_live
        ON oauth_identities(provider, provider_subject_id)
        WHERE deleted_at IS NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_oauth_identities_user_provider_live
        ON oauth_identities(user_id, provider)
        WHERE deleted_at IS NULL
        """
    )
    op.execute(
        """
        CREATE TABLE refresh_tokens (
            jti UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            family_id UUID NOT NULL,
            parent_jti UUID NULL REFERENCES refresh_tokens(jti) ON DELETE SET NULL,
            access_jti UUID NOT NULL UNIQUE,
            access_expires_at TIMESTAMPTZ NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            redeemed_at TIMESTAMPTZ NULL,
            revoked_at TIMESTAMPTZ NULL,
            ip_address VARCHAR(45) NULL,
            request_id VARCHAR(128) NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_refresh_tokens_user_issued_at ON refresh_tokens(user_id, issued_at DESC)")
    op.execute("CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens(family_id)")
    op.execute("CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens(expires_at)")
    op.execute(
        """
        CREATE TABLE loopback_auth_pending (
            state VARCHAR(255) PRIMARY KEY,
            client_id VARCHAR(255) NOT NULL,
            code_challenge VARCHAR(128) NOT NULL,
            redirect_uri VARCHAR(255) NOT NULL,
            idp_state VARCHAR(64) NOT NULL UNIQUE,
            idp_nonce VARCHAR(64) NOT NULL,
            console_authz_code_hash CHAR(64) NULL,
            user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_loopback_auth_pending_idp_state ON loopback_auth_pending(idp_state)")
    op.execute("CREATE INDEX ix_loopback_auth_pending_expires_at ON loopback_auth_pending(expires_at)")
    op.execute(
        """
        CREATE UNIQUE INDEX ux_loopback_auth_pending_authz_code_live
        ON loopback_auth_pending(console_authz_code_hash)
        WHERE console_authz_code_hash IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE TABLE device_flow_pending (
            device_code VARCHAR(255) PRIMARY KEY,
            polling_secret_hash VARCHAR(128) NOT NULL,
            provider VARCHAR(50) NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            last_polled_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_device_flow_pending_expires_at ON device_flow_pending(expires_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_device_flow_pending_expires_at")
    op.execute("DROP TABLE IF EXISTS device_flow_pending")
    op.execute("DROP INDEX IF EXISTS ux_loopback_auth_pending_authz_code_live")
    op.execute("DROP INDEX IF EXISTS ix_loopback_auth_pending_expires_at")
    op.execute("DROP INDEX IF EXISTS ix_loopback_auth_pending_idp_state")
    op.execute("DROP TABLE IF EXISTS loopback_auth_pending")
    op.execute("DROP INDEX IF EXISTS ix_refresh_tokens_expires_at")
    op.execute("DROP INDEX IF EXISTS ix_refresh_tokens_family_id")
    op.execute("DROP INDEX IF EXISTS ix_refresh_tokens_user_issued_at")
    op.execute("DROP TABLE IF EXISTS refresh_tokens")
    op.execute("DROP INDEX IF EXISTS ux_oauth_identities_user_provider_live")
    op.execute("DROP INDEX IF EXISTS ux_oauth_identities_provider_subject_live")
    op.execute("DROP TABLE IF EXISTS oauth_identities")
