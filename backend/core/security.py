# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
Central security module.  All cryptographic primitives and auth guards live
here.  No other module should touch raw crypto directly.

Responsibilities
----------------
1. Password hashing / verification          (passlib pbkdf2_sha256)
2. Vault-item encryption / decryption       (AES-256-GCM)
3. JWT creation / decoding                  (PyJWT / HS256)
4. FastAPI dependency guards                (get_current_user, require_admin)
"""

import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt as _jwt        # PyJWT
from passlib.hash import pbkdf2_sha256 as _pbkdf2  # pure Python, no binary deps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from core.config import settings
from database import get_db

# ---------------------------------------------------------------------------
# 1.  pbkdf2_sha256 – password hashing  (pure Python, no glibc constraint)
# ---------------------------------------------------------------------------
# Switched from bcrypt because bcrypt 4.x abi3 wheels require GLIBC_2.34 and
# cannot load on RHEL 8 (glibc 2.28).  passlib's pbkdf2_sha256 is entirely
# pure Python and provides equivalent security.  Default iteration count is
# 600 000 (passlib 2024 default); adjust via using().
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> tuple[str, str]:
    """
    Hash a plaintext password with PBKDF2-SHA256 (600 000 rounds).

    Returns
    -------
    password_hash : str   Full passlib hash string  e.g. "$pbkdf2-sha256$..."
    salt          : str   Placeholder kept for DB schema compat; actual salt is
                          embedded inside the hash string (passlib convention).
    """
    password_hash = _pbkdf2.using(rounds=600_000).hash(plain)
    # salt field kept for DB schema compatibility; passlib embeds salt in hash
    return password_hash, "pbkdf2-embedded"


def verify_password(plain: str, stored_hash: str) -> bool:
    """
    Constant-time verification of a plaintext password against a
    pbkdf2_sha256 hash produced by :func:`hash_password`.
    """
    return _pbkdf2.verify(plain, stored_hash)


# ---------------------------------------------------------------------------
# 2.  AES-256-GCM – vault encryption
# ---------------------------------------------------------------------------


def _get_master_key() -> bytes:
    """
    Decode the base64-encoded MASTER_ENCRYPTION_KEY from the environment.
    Called at use-time (not import-time) so the key is never cached at module
    load.  Must be exactly 32 bytes after decoding.
    """
    key = base64.b64decode(settings.master_encryption_key)
    if len(key) != 32:
        raise RuntimeError("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def encrypt_value(plaintext: str) -> tuple[str, str]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Each call generates a fresh 12-byte (96-bit) random nonce – nonce reuse
    with the same key would be catastrophic for GCM, so we never reuse.

    Returns
    -------
    encrypted_b64 : str   base64( ciphertext || 16-byte GCM tag )
    iv_b64        : str   base64( 12-byte nonce )
    """
    key = _get_master_key()
    iv = secrets.token_bytes(12)          # 96-bit nonce per NIST SP 800-38D
    aesgcm = AESGCM(key)
    # AAD (additional authenticated data) is None – we don't need it here
    ct_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return (
        base64.b64encode(ct_and_tag).decode("ascii"),
        base64.b64encode(iv).decode("ascii"),
    )


def encrypt_value_with_iv(plaintext: str, iv_b64: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM using a provided IV.

    WARNING: This should only be used when encrypting multiple fields that
    logically belong together. Reusing IVs is generally a security risk.

    Returns
    -------
    encrypted_b64 : str   base64( ciphertext || 16-byte GCM tag )
    """
    key = _get_master_key()
    iv = base64.b64decode(iv_b64)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(ct_and_tag).decode("ascii")


def decrypt_value(encrypted_b64: str, iv_b64: str) -> str:
    """
    Decrypt a value produced by :func:`encrypt_value`.

    Raises ``ValueError`` if the GCM authentication tag does not match
    (i.e. the data has been tampered with or the key is wrong).
    """
    key = _get_master_key()
    iv = base64.b64decode(iv_b64)
    ct_and_tag = base64.b64decode(encrypted_b64)
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(iv, ct_and_tag, None)
    except Exception as exc:
        raise ValueError("Decryption failed – data may be tampered") from exc
    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# 3.  JWT – access tokens
# ---------------------------------------------------------------------------


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Sign a JWT with HS256.

    *data* should contain at minimum: sub (email), user_id, role.
    An ``exp`` claim is added automatically.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode["exp"] = expire
    return _jwt.encode(to_encode, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT.  Raises HTTP 401 on any failure (expired,
    bad signature, malformed).
    """
    try:
        return _jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


# ---------------------------------------------------------------------------
# 4.  FastAPI dependency guards
# ---------------------------------------------------------------------------

# The tokenUrl here is only used by the auto-generated OpenAPI docs;
# the actual login endpoint is POST /auth/login.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db=Depends(get_db),
):
    """
    Dependency: decode the JWT, load the User row, verify the account is
    active.  Returns the User ORM instance.

    Raises 401 if the token is invalid or the user is gone/disabled.
    """
    payload = decode_access_token(token)

    # Lazy import to avoid circular dependency at module load time
    from models.user import User  # noqa: E402

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


def require_admin(current_user=Depends(get_current_user)):
    """
    Dependency: wraps :func:`get_current_user` and additionally asserts
    ``role == 'admin'``.  Raises 403 otherwise.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# -- IP Address extraction ----------------------------------------------------


def get_client_ip(request: Request) -> str:
    """
    Extract the client IP address from the request.
    Checks X-Forwarded-For header first (for proxies), then falls back to client host.
    Returns the IP address as a string (supports both IPv4 and IPv6).
    """
    # Check X-Forwarded-For header (common when behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For can contain multiple IPs, take the first (original client)
        return forwarded.split(",")[0].strip()

    # Fall back to direct client address
    if request.client:
        return request.client.host

    return "unknown"
