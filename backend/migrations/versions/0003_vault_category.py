"""Add category column to vault_items

Revision ID: 0003_vault_category
Revises: 0002_last_login_audit
Create Date: 2026-02-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_vault_category"
down_revision = "0002_last_login_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column(
            "category",
            sa.String(32),
            nullable=False,
            server_default="login",
        ),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "category")
