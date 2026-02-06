"""Add api_key column for API credentials

Revision ID: 0010_api_key
Revises: 0009_db_port
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_api_key"
down_revision = "0009_db_port"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column("api_key", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "api_key")
