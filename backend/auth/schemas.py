# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""Pydantic request / response models for the auth endpoints."""

from pydantic import BaseModel


# -- Requests --------------------------------------------------------------


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# -- Responses -------------------------------------------------------------


class LoginResponse(BaseModel):
    access_token: str
    token_type: str  # always "bearer"
    force_password_change: bool


class UserInfoResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    force_password_change: bool

    model_config = {"from_attributes": True}
