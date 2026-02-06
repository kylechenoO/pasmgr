"""Add port column for database entries

Revision ID: 0009_db_port
Revises: 0008_audit_request_ip
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_db_port"
down_revision = "0008_audit_request_ip"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_items",
        sa.Column("port", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_items", "port")
