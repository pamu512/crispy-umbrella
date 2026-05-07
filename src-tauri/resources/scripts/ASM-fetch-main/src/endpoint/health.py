"""
Deep health checks for operations readiness (filesystem, configuration, logging).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from config.settings import Settings

router = APIRouter()


def _check_filesystem_writable() -> tuple[bool, dict[str, Any]]:
    """Verify we can create a directory (if needed) and write a temporary file."""
    raw = os.environ.get("ASM_HEALTH_WRITABLE_DIR", "").strip()
    base = Path(raw).expanduser().resolve() if raw else Path(tempfile.gettempdir()).resolve()
    detail: dict[str, Any] = {"path": str(base)}
    try:
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="asm-health-", dir=base, delete=True) as tmp:
            tmp.write(b"ok")
            tmp.flush()
        detail["writable"] = True
        return True, detail
    except OSError as e:
        detail["error"] = str(e)
        return False, detail


def _check_environment() -> tuple[bool, dict[str, Any]]:
    """
    Verify required configuration is present (Settings / env).

    Treats explicitly empty env overrides as failures; validates DATABASE_URL shape.
    """
    detail: dict[str, Any] = {}
    ok = True

    if "DATABASE_URL" in os.environ and not (os.environ.get("DATABASE_URL") or "").strip():
        ok = False
        detail["DATABASE_URL"] = "set but empty"

    url = (Settings.DATABASE_URL or "").strip()
    if not url:
        ok = False
        detail["DATABASE_URL_resolved"] = "empty"
    elif not (
        url.startswith("postgresql://")
        or url.startswith("postgres://")
        or url.startswith("postgresql+")
        or url.startswith("sqlite:")
    ):
        ok = False
        detail["DATABASE_URL_resolved"] = "invalid database URL scheme"

    broker = (Settings.CELERY_BROKER_URL or "").strip()
    backend = (Settings.CELERY_RESULT_BACKEND or "").strip()
    if not broker:
        ok = False
        detail["CELERY_BROKER_URL"] = "empty"
    if not backend:
        ok = False
        detail["CELERY_RESULT_BACKEND"] = "empty"

    detail["dotenv_loaded"] = True  # Settings module imports load_dotenv()
    return ok, detail


def _check_logging() -> tuple[bool, dict[str, Any]]:
    from logger import logging_health_ok

    fine, message = logging_health_ok()
    return fine, {"active": fine, "detail": message}


@router.get("/health")
def health() -> JSONResponse:
    """
    Deep readiness probe: local FS writable, env/config loaded, logging subsystem active.

    Returns **503** if any check fails.
    """
    checks: dict[str, Any] = {}

    fs_ok, fs_detail = _check_filesystem_writable()
    checks["filesystem"] = {"ok": fs_ok, **fs_detail}

    env_ok, env_detail = _check_environment()
    checks["environment"] = {"ok": env_ok, **env_detail}

    log_ok, log_detail = _check_logging()
    checks["logging"] = {"ok": log_ok, **log_detail}

    healthy = fs_ok and env_ok and log_ok
    body: dict[str, Any] = {"status": "healthy" if healthy else "unhealthy", "checks": checks}

    return JSONResponse(status_code=200 if healthy else 503, content=body)
