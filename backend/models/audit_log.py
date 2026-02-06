# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""AuditLog ORM model – tracks every admin-facing action."""

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func

from database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # The admin who performed the action
    admin_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # The user who was the target of the action (NULL for login events)
    target_user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action = Column(String(64), nullable=False, index=True)   # e.g. "create_user"
    detail = Column(Text, nullable=True)                      # human-readable note
    request_ip = Column(String(45), nullable=True)            # Client IP address (supports IPv6)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
