"""Initial schema – users and vault_items

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-05

Creates both core tables with the correct character set, collation,
foreign-key constraints, and indexes required by the application.
"""

from alembic import op
import sqlalchemy as sa

# Alembic revision identifiers
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -- users ----------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("salt", sa.String(255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("admin", "user", name="user_role"),
            nullable=False,
            server_default="user",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "force_password_change",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # InnoDB + utf8mb4 is set at the MySQL level; SQLAlchemy/Alembic
        # respects the database default if the DB was created with utf8mb4.
    )

    # -- vault_items ----------------------------------------------------
    op.create_table(
        "vault_items",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        # base64( ciphertext || 16-byte GCM tag ) – never plaintext
        sa.Column("encrypted_password", sa.Text(), nullable=False),
        # base64( 12-byte AES-GCM nonce )
        sa.Column("iv", sa.String(64), nullable=False),
        sa.Column("url", sa.String(2048), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # Index on the most common query: "all items for user X"
    op.create_index("idx_vault_items_user_id", "vault_items", ["user_id"])


def downgrade() -> None:
    op.drop_index("idx_vault_items_user_id", table_name="vault_items")
    op.drop_table("vault_items")
    op.drop_table("users")
