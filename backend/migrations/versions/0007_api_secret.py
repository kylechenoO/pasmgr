"""Add api_secret column for API credentials

Revision ID: 0007_api_secret
Revises: 0006_private_key
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_api_secret"
down_revision = "0006_private_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column("api_secret", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "api_secret")
