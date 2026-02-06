"""Add last_login to users and create audit_logs table

Revision ID: 0002_add_last_login_and_audit_logs
Revises: 0001_initial
Create Date: 2026-02-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_last_login_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -- users.last_login -----------------------------------------------
    op.add_column(
        "users",
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # -- audit_logs -----------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "admin_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "target_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_index("idx_audit_logs_admin_id", "audit_logs", ["admin_id"])
    op.create_index("idx_audit_logs_target_user_id", "audit_logs", ["target_user_id"])
    op.create_index("idx_audit_logs_action", "audit_logs", ["action"])
    op.create_index("idx_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("idx_audit_logs_action", table_name="audit_logs")
    op.drop_index("idx_audit_logs_target_user_id", table_name="audit_logs")
    op.drop_index("idx_audit_logs_admin_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_column("users", "last_login")
