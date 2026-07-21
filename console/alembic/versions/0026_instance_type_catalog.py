"""Add the instance_type_catalog singleton table (provider catalog last-known-good).

Revision ID: 0026_instance_type_catalog
Revises: 0025_cvm_disk_size
"""

from typing import Union

from alembic import op

revision = "0026_instance_type_catalog"
down_revision: Union[str, None] = "0025_cvm_disk_size"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE instance_type_catalog (
            id SMALLINT PRIMARY KEY CHECK (id = 1),
            payload JSONB NOT NULL,
            fetched_at TIMESTAMPTZ NULL,
            source TEXT NOT NULL,
            last_refresh_error JSONB NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS instance_type_catalog")
