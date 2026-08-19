"""merge the public and pre-Umbra compatibility lineages

Revision ID: 0033_public_legacy_merge
Revises: 0028_secret_envelope_v2, 0032_attn_unreachable
Create Date: 2026-08-13

The merge lets a database at the exact deployed pre-Umbra head run the real
public secret-envelope migration and converge with a fresh Umbra database. It
does not remove dormant legacy schema or data.
"""


revision = "0033_public_legacy_merge"
down_revision = ("0028_secret_envelope_v2", "0032_attn_unreachable")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    raise RuntimeError(
        "downgrade across the public/pre-Umbra merge is unsupported; "
        "restore the pre-upgrade database backup"
    )
