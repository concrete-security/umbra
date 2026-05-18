"""audit_anchors redaction_event_seq

Revision ID: 0018_audit_anchors_redaction_seq
Revises: 0017_tdx_image_measurements
Create Date: 2026-05-18

"""

from typing import Sequence, Union

from alembic import op

revision: str = "0018_audit_anchors_redaction_seq"
down_revision: Union[str, None] = "0017_tdx_image_measurements"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_anchors ADD COLUMN IF NOT EXISTS redaction_event_seq BIGINT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE audit_anchors DROP COLUMN IF EXISTS redaction_event_seq")
