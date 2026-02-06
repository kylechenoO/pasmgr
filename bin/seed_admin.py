# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
Bootstrap script – creates the first admin user.

Run once after the initial migration:
    python bin/seed_admin.py

The script reads FIRST_ADMIN_EMAIL and FIRST_ADMIN_PASSWORD from etc/app.conf
file.  After the row is inserted those env vars are no longer used by the
application.

The admin account starts with ``force_password_change = True``, so the
operator must set a permanent password on first login.
"""

import sys
import os

# ---------------------------------------------------------------------------
# Path setup so backend modules are importable
# ---------------------------------------------------------------------------
# bin/seed_admin.py  →  ../  →  project root
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR  = os.path.join(_PROJECT_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.config import settings          # noqa: E402
from core.security import hash_password   # noqa: E402
from database import SessionLocal         # noqa: E402
from models.user import User              # noqa: E402


def seed():
    if not settings.first_admin_email or not settings.first_admin_password:
        print("[seed_admin] FIRST_ADMIN_EMAIL or FIRST_ADMIN_PASSWORD not set in etc/app.conf – nothing to do.")
        return

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.first_admin_email).first()
        if existing:
            print(f"[seed_admin] Admin '{settings.first_admin_email}' already exists – skipping.")
            return

        password_hash, salt = hash_password(settings.first_admin_password)
        admin = User(
            email=settings.first_admin_email,
            password_hash=password_hash,
            salt=salt,
            role="admin",
            is_active=True,
            force_password_change=True,
        )
        db.add(admin)
        db.commit()
        print(f"[seed_admin] Admin '{settings.first_admin_email}' created successfully.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
