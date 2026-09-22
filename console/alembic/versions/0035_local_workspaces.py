"""Console-owned local workspace leases and traffic attribution."""
from alembic import op

revision = "0035_local_workspaces"
down_revision = "0034_connect_oauth_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for action in ("LOCAL_WORKSPACE_STARTED", "LOCAL_WORKSPACE_STOPPED"):
        op.execute(f"ALTER TYPE audit_action ADD VALUE '{action}'")
    op.execute("""
        CREATE TABLE local_workspaces (
            id UUID PRIMARY KEY,
            entity_id UUID NOT NULL REFERENCES entities(id),
            owner_id UUID NOT NULL REFERENCES users(id),
            security_cvm_id UUID NOT NULL REFERENCES security_cvms(id),
            profile_ids UUID[] NOT NULL CHECK (cardinality(profile_ids) BETWEEN 1 AND 16),
            proxy_token_hash CHAR(64) NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_local_workspaces_entity ON local_workspaces(entity_id, owner_id)")
    op.execute("ALTER TABLE traffic_logs ADD COLUMN local_workspace_id UUID REFERENCES local_workspaces(id)")
    op.execute("ALTER TABLE traffic_logs ADD CONSTRAINT traffic_single_identity CHECK (cvm_id IS NULL OR local_workspace_id IS NULL)")


def downgrade() -> None:
    op.execute("ALTER TABLE traffic_logs DROP COLUMN local_workspace_id")
    op.execute("DROP TABLE local_workspaces")
