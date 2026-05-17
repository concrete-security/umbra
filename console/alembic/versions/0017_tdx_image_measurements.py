"""tdx image measurements

Revision ID: 0017_tdx_image_measurements
Revises: 0016_drop_sc_ingest_plaintext
Create Date: 2026-05-16
"""

from alembic import op


revision = "0017_tdx_image_measurements"
down_revision = "0016_drop_sc_ingest_plaintext"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cvms ALTER COLUMN expected_image_measurement TYPE VARCHAR(96)")
    op.execute("ALTER TABLE cvms ALTER COLUMN image_measurement TYPE VARCHAR(96)")
    op.execute("ALTER TABLE security_cvms ALTER COLUMN expected_image_measurement TYPE VARCHAR(96)")
    op.execute("ALTER TABLE security_cvms ALTER COLUMN image_measurement TYPE VARCHAR(96)")


def downgrade() -> None:
    op.execute("ALTER TABLE cvms ALTER COLUMN expected_image_measurement TYPE CHAR(64) USING left(expected_image_measurement, 64)")
    op.execute("ALTER TABLE cvms ALTER COLUMN image_measurement TYPE CHAR(64) USING left(image_measurement, 64)")
    op.execute(
        "ALTER TABLE security_cvms ALTER COLUMN expected_image_measurement TYPE CHAR(64) USING left(expected_image_measurement, 64)"
    )
    op.execute("ALTER TABLE security_cvms ALTER COLUMN image_measurement TYPE CHAR(64) USING left(image_measurement, 64)")
