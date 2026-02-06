"""
Application configuration.
All secrets and connection strings are loaded exclusively from environment
variables (via .env file).  Nothing sensitive is hard-coded here.
"""

from pathlib import Path

from pydantic_settings import BaseSettings

# Project root is two levels up from this file  (backend/core/config.py → pasmgr/)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # Database
    database_url: str  # e.g. mysql+pymysql://user:pass@localhost:3306/pasmgr

    # JWT signing secret – must be a long, random string
    secret_key: str

    # AES-256 master key – base64-encoded 32 random bytes.
    # This key is NEVER written to the database or any log.
    master_encryption_key: str

    # Used only by seed_admin.py to bootstrap the first admin account.
    # After seeding these values are inert.
    first_admin_email: str = ""
    first_admin_password: str = ""

    # Token lifetime (1 week = 7 days * 24 hours * 60 minutes)
    access_token_expire_minutes: int = 10080

    # app.conf lives in etc/ – resolved relative to the project root so that
    # the file is found regardless of the working directory.
    model_config = {"env_file": str(_PROJECT_ROOT / "etc" / "app.conf")}


# Module-level singleton – import this everywhere: from core.config import settings
settings = Settings()
