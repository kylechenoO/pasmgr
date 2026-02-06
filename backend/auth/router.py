# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
Auth endpoints – login, password change, current-user info.

Security notes
--------------
* Login returns the *same* error message whether the email doesn't exist or
  the password is wrong.  This prevents user-enumeration attacks.
* change-password verifies the old password before accepting the new one,
  so a stolen (but not yet expired) token alone cannot reset the password.
"""

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from core.security import (
    verify_password,
    hash_password,
    create_access_token,
    get_current_user,
)
from models.user import User
from models.audit_log import AuditLog
from auth.schemas import (
    LoginRequest,
    LoginResponse,
    ChangePasswordRequest,
    UserInfoResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Generic message used for both "no such email" and "wrong password"
_LOGIN_FAIL = "Invalid email or password"


def _validate_new_password(pw: str) -> str | None:
    """
    Return an error string if the password does not meet the minimum policy,
    or None if it is acceptable.

    Policy: >= 8 chars, at least one uppercase, one lowercase, one digit.
    """
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", pw):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", pw):
        return "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", pw):
        return "Password must contain at least one digit"
    return None


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate and return a signed JWT."""
    user = db.query(User).filter(User.email == body.email).first()

    # Unified failure path – no information leaks about whether the email exists
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_LOGIN_FAIL)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account disabled",
        )

    # Record login timestamp and audit event
    user.last_login = datetime.now(timezone.utc)
    db.add(AuditLog(admin_id=None, target_user_id=user.id, action="user_login"))
    db.commit()

    token = create_access_token(
        {"sub": user.email, "user_id": user.id, "role": user.role}
    )
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        force_password_change=user.force_password_change,
    )


# ---------------------------------------------------------------------------
# PUT /auth/change-password
# ---------------------------------------------------------------------------


@router.put("/change-password")
def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change the authenticated user's login password.
    Also clears the force_password_change flag.
    """
    if not verify_password(body.old_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect",
        )

    err = _validate_new_password(body.new_password)
    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    new_hash, new_salt = hash_password(body.new_password)
    current_user.password_hash = new_hash
    current_user.salt = new_salt
    current_user.force_password_change = False
    db.commit()

    return {"detail": "Password changed successfully"}


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get("/me", response_model=UserInfoResponse)
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's public profile (no secrets)."""
    return current_user
