#!/bin/bash
# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# start.sh – launch the Password Manager backend
#
# Usage
#   ./start.sh            # foreground (default)
#   ./start.sh &          # background
#
# The script resolves all paths relative to its own location so it can be
# invoked from any working directory.
# ---------------------------------------------------------------------------
set -euo pipefail

# -- Resolve project root (one level up from bin/) ------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
LOG_DIR="$PROJECT_ROOT/log"

# -- Ensure log/ exists ----------------------------------------------------
mkdir -p "$LOG_DIR"

# -- Pick the Python interpreter -------------------------------------------
# Priority: bin/python at project root > venv/bin/python > system python3
if [[ -x "$PROJECT_ROOT/bin/python" ]]; then
    PYTHON="$PROJECT_ROOT/bin/python"
    VENV_ACTIVE="yes"
elif [[ -x "$PROJECT_ROOT/venv/bin/python" ]]; then
    PYTHON="$PROJECT_ROOT/venv/bin/python"
    VENV_ACTIVE="yes"
else
    PYTHON="python3"
    VENV_ACTIVE="no"
    echo "[start.sh] WARNING: No virtual environment found!"
    echo "[start.sh] Please create one: python3 -m venv . && source bin/activate && pip install -r requirements.txt"
fi

# -- Port (override via environment variable) -----------------------------
PORT="${PASMGR_PORT:-8001}"

# -- Log file for uvicorn stdout/stderr ------------------------------------
UVICORN_LOG="$LOG_DIR/uvicorn.log"

echo "[start.sh] Project root : $PROJECT_ROOT"
echo "[start.sh] Python       : $PYTHON"
echo "[start.sh] Virtual env  : $VENV_ACTIVE"
echo "[start.sh] Port         : $PORT"
echo "[start.sh] Uvicorn log  : $UVICORN_LOG"

# -- Verify uvicorn is available -------------------------------------------
if ! "$PYTHON" -m uvicorn --version &>/dev/null; then
    echo "[start.sh] ERROR: uvicorn not found!"
    echo "[start.sh] Please install dependencies: pip install -r requirements.txt"
    exit 1
fi

# -- Launch uvicorn --------------------------------------------------------
cd "$BACKEND_DIR"
exec "$PYTHON" -m uvicorn main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --log-level info \
    2>&1 | tee -a "$UVICORN_LOG"
