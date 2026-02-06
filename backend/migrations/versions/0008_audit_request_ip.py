"""Add request_ip column to audit_logs

Revision ID: 0008_audit_request_ip
Revises: 0007_api_secret
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_audit_request_ip"
down_revision = "0007_api_secret"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("request_ip", sa.String(45), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_logs", "request_ip")
