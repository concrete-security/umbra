"""add traffic_logs.decision for first-class enforcement-decision queries

Revision ID: 0027_traffic_logs_decision
Revises: 0026_user_secret_material
Create Date: 2026-07-10
"""

from alembic import op


revision = "0027_traffic_logs_decision"
down_revision = "0026_user_secret_material"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable: rows ingested before this column existed (and any older SC that
    # does not emit `decision`) simply carry NULL. The SC populates it going
    # forward ("allowed", a block reason such as "secret_injection_unfulfilled",
    # or "websocket_frame_dropped") so a blocked request is diagnosable from the
    # logs by reason without reproducing it.
    op.execute(
        """
        ALTER TABLE traffic_logs
        ADD COLUMN IF NOT EXISTS decision VARCHAR(64) NULL
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE traffic_logs DROP COLUMN IF EXISTS decision")
