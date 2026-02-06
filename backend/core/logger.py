# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
Centralised logging configuration.

All log settings (levels, rotation, format …) live in  etc/logging.conf.
This module resolves the log-file path, patches it into the config text, and
applies it via the standard-library fileConfig loader.

Import the ready-made logger anywhere:
    from core.logger import logger
"""

import logging
import logging.config
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# project root: backend/core/logger.py  →  ../../  →  pasmgr/
_PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent
_LOG_DIR       = _PROJECT_ROOT / "log"
_LOG_FILE      = _LOG_DIR / "app.log"
_LOGGING_CONF  = _PROJECT_ROOT / "etc" / "logging.conf"

# Ensure the log/ directory exists before the handler tries to open the file
_LOG_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Load & apply logging.conf
# ---------------------------------------------------------------------------
# logging.conf uses %(log_file)s as a placeholder.  We read the raw text,
# replace it with the real absolute path, then feed the result to fileConfig
# via a ConfigParser-compatible string.

import configparser as _cp
import io as _io

_raw = _LOGGING_CONF.read_text(encoding="utf-8")
_raw = _raw.replace("%(log_file)s", str(_LOG_FILE))

# RawConfigParser is required: the logging format strings contain %(asctime)s
# etc. which ConfigParser would try to interpolate and fail on.
_parser = _cp.RawConfigParser()
_parser.read_string(_raw)

logging.config.fileConfig(_parser, disable_existing_loggers=False)

# ---------------------------------------------------------------------------
# Module-level handle
# ---------------------------------------------------------------------------
logger = logging.getLogger("pasmgr")
