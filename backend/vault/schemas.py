# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""Pydantic request / response models for the vault endpoints."""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel


# -- Requests --------------------------------------------------------------
# The client sends the *plaintext* password; the server encrypts it before
# persisting.  The encrypted_password and iv columns are populated server-side
# and never accepted from the client.


VALID_CATEGORIES = {
    "login",
    "ssh_key",
    "api_credential",
    "database",
}


class VaultItemCreate(BaseModel):
    category: str = "login"
    title: str
    username: Optional[str] = None
    plaintext_password: Optional[str] = None
    url: Optional[str] = None
    port: Optional[int] = None
    notes: Optional[str] = None
    public_key: Optional[str] = None
    private_key: Optional[str] = None
    api_key: Optional[str] = None
    plaintext_api_secret: Optional[str] = None


class VaultItemUpdate(BaseModel):
    category: Optional[str] = None
    title: Optional[str] = None
    username: Optional[str] = None
    plaintext_password: Optional[str] = None  # if provided the server re-encrypts
    url: Optional[str] = None
    port: Optional[int] = None
    notes: Optional[str] = None
    public_key: Optional[str] = None
    private_key: Optional[str] = None
    api_key: Optional[str] = None
    plaintext_api_secret: Optional[str] = None


# -- Responses -------------------------------------------------------------
# Responses include the *encrypted* password and IV – never the plaintext.
# Use GET /vault/items/{id}/decrypt to retrieve the plaintext on demand.


class VaultItemResponse(BaseModel):
    id: int
    user_id: int
    category: str
    title: str
    username: str
    encrypted_password: str
    iv: str
    url: Optional[str]
    port: Optional[int]
    notes: Optional[str]
    public_key: Optional[str]
    private_key: Optional[str]
    api_key: Optional[str]
    api_secret: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VaultItemListResponse(BaseModel):
    items: List[VaultItemResponse]
