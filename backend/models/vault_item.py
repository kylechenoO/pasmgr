# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""VaultItem ORM model."""

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func

from database import Base


class VaultItem(Base):
    __tablename__ = "vault_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Cascade delete: removing a user removes all their vault items atomically.
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category = Column(String(32), nullable=False, server_default="login")
    title = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False, server_default="")
    # Stores base64( ciphertext || 16-byte GCM authentication tag ).
    # Never contains plaintext. (empty string encrypted for secure_note)
    encrypted_password = Column(Text, nullable=False)
    # Stores base64( 12-byte AES-GCM nonce ).
    iv = Column(String(64), nullable=False)
    url = Column(String(2048), nullable=True)
    port = Column(Integer, nullable=True)  # For database connections
    notes = Column(Text, nullable=True)
    public_key = Column(Text, nullable=True)  # For SSH keys
    private_key = Column(Text, nullable=True)  # For SSH keys (encrypted private key)
    api_key = Column(Text, nullable=True)  # For API credentials (plaintext key/ID)
    api_secret = Column(Text, nullable=True)  # For API credentials (encrypted secret)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
