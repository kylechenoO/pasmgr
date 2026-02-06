"""Add public_key column for SSH keys

Revision ID: 0005_public_key
Revises: 0004_username_default
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_public_key"
down_revision = "0004_username_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column("public_key", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "public_key")
