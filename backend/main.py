# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
FastAPI application factory.

Responsibilities
----------------
* Instantiate the FastAPI app.
* Register CORS middleware.
* Mount the three feature routers (auth, admin, vault).
* Mount the frontend static files so a single ``uvicorn`` process serves
  both the API and the HTML/CSS/JS.
* Expose a /health endpoint for container liveness checks.

Production note
---------------
CORS allow_origins is set to localhost only.  In a production deployment
this must be changed to the exact frontend origin.
"""

import time
from pathlib import Path

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from auth.router import router as auth_router
from admin.router import router as admin_router
from vault.router import router as vault_router
from core.logger import logger

app = FastAPI(title="Password Manager", version="1.0.0")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# In development we allow localhost:8000 (same origin when served as static).
# Tighten to your production domain before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Request-logging middleware
# ---------------------------------------------------------------------------
# Logs every inbound request: method, path, client IP, status, latency.
# Sensitive paths (login payload, password fields) are NOT echoed – only the
# URL and metadata are recorded.


class _RequestLogMiddleware(BaseHTTPMiddleware):
    """Log method, path, client IP, response status and latency (ms)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response: Response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000

        client_ip = request.client.host if request.client else "unknown"

        logger.info(
            "%s %s | client=%s status=%d latency=%.1fms",
            request.method,
            request.url.path,
            client_ip,
            response.status_code,
            elapsed_ms,
        )
        return response


app.add_middleware(_RequestLogMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(vault_router)

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def _on_startup():
    logger.info("Password Manager service starting up")


@app.on_event("shutdown")
async def _on_shutdown():
    logger.info("Password Manager service shutting down")


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Static files – frontend
# ---------------------------------------------------------------------------
# Mounted *after* the API routers so that /auth/*, /admin/*, /vault/* are
# handled by FastAPI first.  ``html=True`` makes the mount serve index.html
# for directory requests and allows direct access to login.html etc.
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
