# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""Pydantic request / response models for the admin endpoints."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


# -- Requests --------------------------------------------------------------


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "user"  # "admin" or "user"


class ResetPasswordRequest(BaseModel):
    new_password: str


class ChangeRoleRequest(BaseModel):
    role: str  # "admin" or "user"


# -- Responses -------------------------------------------------------------


class UserRow(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    users: List[UserRow]


# -- Audit log responses ---------------------------------------------------


class AuditLogRow(BaseModel):
    id: int
    admin_email: Optional[str] = None       # resolved from admin_id join
    target_email: Optional[str] = None      # resolved from target_user_id join
    action: str
    detail: Optional[str] = None
    request_ip: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogRow]
