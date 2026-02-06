"""Make username default to empty string for secure notes

Revision ID: 0004_username_default
Revises: 0003_vault_category
Create Date: 2026-02-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_username_default"
down_revision = "0003_vault_category"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alter username to have server_default empty string (allows secure_note to omit it)
    op.alter_column(
        "vault_items",
        "username",
        existing_type=sa.String(255),
        server_default="",
        nullable=False,
    )


def downgrade() -> None:
    # Remove the server_default
    op.alter_column(
        "vault_items",
        "username",
        existing_type=sa.String(255),
        server_default=None,
        nullable=False,
    )
