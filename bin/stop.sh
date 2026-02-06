#!/bin/bash
# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# stop.sh – gracefully stop the Password Manager backend
#
# Kills any uvicorn process that is running main:app on the configured port.
# ---------------------------------------------------------------------------
set -euo pipefail

PORT="${PASMGR_PORT:-8001}"

echo "[stop.sh] Looking for uvicorn on port $PORT …"

# Try lsof first (macOS / most Linux), fall back to ss/netstat
PID=""
if command -v lsof &>/dev/null; then
    PID=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
elif command -v ss &>/dev/null; then
    PID=$(ss -tlnp | awk -v port=":${PORT} " '$4 ~ port {print $7}' | grep -oP 'pid=\K[0-9]+' || true)
fi

if [[ -z "$PID" ]]; then
    echo "[stop.sh] Nothing listening on port $PORT – already stopped."
    exit 0
fi

echo "[stop.sh] Sending SIGTERM to PID(s): $PID"
kill -TERM $PID 2>/dev/null || true

# Wait up to 5 seconds for clean shutdown, then SIGKILL
for i in {1..5}; do
    sleep 1
    ALIVE=$(kill -0 $PID 2>/dev/null && echo yes || echo no)
    if [[ "$ALIVE" == "no" ]]; then
        echo "[stop.sh] Process stopped cleanly."
        exit 0
    fi
done

echo "[stop.sh] Process still alive – sending SIGKILL …"
kill -KILL $PID 2>/dev/null || true
echo "[stop.sh] Done."
