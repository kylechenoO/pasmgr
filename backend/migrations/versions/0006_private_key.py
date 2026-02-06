"""Add private_key column for SSH keys

Revision ID: 0006_private_key
Revises: 0005_public_key
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_private_key"
down_revision = "0005_public_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column("private_key", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "private_key")
