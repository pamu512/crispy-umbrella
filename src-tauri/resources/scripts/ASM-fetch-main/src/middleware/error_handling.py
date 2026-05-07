"""
Central exception handling with PII-safe logging and standardized JSON errors.

Every response includes ``X-Request-ID`` and error payloads include ``request_id``.
"""

from __future__ import annotations

import json
import logging
import re
import traceback
import uuid
from typing import Any

from circuit_breaker import DependencyUnavailableError
from logger import reset_correlation_id, set_correlation_id
from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_INBOUND = re.compile(r"^[A-Za-z0-9\-]{8,128}$")

_LOG = logging.getLogger("asm.api.errors")
_LOG.setLevel(logging.INFO)


def scrub_pii(text: str) -> str:
    """
    Best-effort removal/replacement of common PII patterns from free-form text.

    Does not guarantee completeness; extend patterns as needed for your threat model.
    """
    if not text:
        return text
    s = text
    patterns: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IPV4]"),
        (
            re.compile(
                r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]{3,}\b"
            ),
            "[REDACTED_IPV6]",
        ),
        (
            re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*[^\s&\"']+"),
            r"\1=[REDACTED]",
        ),
        (
            re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
            "Bearer [REDACTED_TOKEN]",
        ),
        (
            re.compile(
                r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
            ),
            "[REDACTED_PHONE]",
        ),
        (
            re.compile(r"\b(?:\d[ -]*?){13,19}\d\b"),
            "[REDACTED_NUMERIC_ID]",
        ),
    ]
    for rx, repl in patterns:
        s = rx.sub(repl, s)
    return s


def scrub_value(value: Any) -> Any:
    """Recursively scrub strings inside structures (for validation error bodies)."""
    if isinstance(value, str):
        return scrub_pii(value)
    if isinstance(value, list):
        return [scrub_value(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub_value(v) for k, v in value.items()}
    return value


def _request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if isinstance(existing, str) and existing:
        return existing
    rid = str(uuid.uuid4())
    request.state.request_id = rid
    return rid


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Assign or propagate ``X-Request-ID`` on every request/response.

    Also binds the logging context ``correlation_id`` (via :func:`set_correlation_id`)
    for the request scope so every log record includes it automatically—no message
    formatting required.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        inbound = request.headers.get(REQUEST_ID_HEADER)
        if inbound and _REQUEST_ID_INBOUND.match(inbound.strip()):
            rid = inbound.strip()
        else:
            rid = str(uuid.uuid4())
        request.state.request_id = rid
        corr_token = set_correlation_id(rid)
        try:
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = rid
            return response
        finally:
            reset_correlation_id(corr_token)


def _error_body(
    *,
    code: str,
    message: str,
    request_id: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        }
    }
    if extra:
        body["error"].update(extra)
    return body


def setup_exception_handlers(app: Any) -> None:
    """Register handlers so specific types win over the generic ``Exception`` handler."""

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        rid = _request_id(request)
        raw_errors = exc.errors()
        scrubbed = scrub_value(raw_errors)
        payload = json.dumps(jsonable_encoder({"errors": scrubbed}), ensure_ascii=False)
        _LOG.warning(
            "Request validation failed [%s]: %s",
            rid,
            scrub_pii(payload),
        )
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder(
                _error_body(
                    code="validation_error",
                    message="Request validation failed",
                    request_id=rid,
                    extra={"details": scrubbed},
                )
            ),
        )

    @app.exception_handler(DependencyUnavailableError)
    async def dependency_unavailable_handler(
        request: Request, exc: DependencyUnavailableError
    ) -> JSONResponse:
        rid = _request_id(request)
        msg = scrub_pii(str(exc))[:2000]
        _LOG.warning("Dependency unavailable [%s]: %s", rid, msg)
        return JSONResponse(
            status_code=503,
            content=jsonable_encoder(
                _error_body(
                    code="dependency_unavailable",
                    message="A required external service is temporarily unavailable.",
                    request_id=rid,
                )
            ),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        rid = _request_id(request)
        detail = exc.detail
        if isinstance(detail, (list, dict)):
            scrubbed_detail = scrub_value(jsonable_encoder(detail))
            msg = json.dumps(scrubbed_detail, ensure_ascii=False)[:2000]
        else:
            msg = scrub_pii(str(detail))[:2000]
        _LOG.warning(
            "HTTPException [%s] status=%s detail=%s",
            rid,
            exc.status_code,
            scrub_pii(str(detail)),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder(
                _error_body(
                    code="http_error",
                    message=msg if exc.status_code != 500 else "Request failed",
                    request_id=rid,
                    extra={"http_status": exc.status_code},
                )
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Handlers are matched by type; HTTPException and RequestValidationError use handlers above.
        rid = _request_id(request)
        summary = f"{type(exc).__name__}: {exc}"
        tb = traceback.format_exc()
        safe_summary = scrub_pii(summary)
        safe_tb = scrub_pii(tb)
        _LOG.error(
            "Unhandled exception [%s]: %s\n%s",
            rid,
            safe_summary,
            safe_tb,
        )
        return JSONResponse(
            status_code=500,
            content=jsonable_encoder(
                _error_body(
                    code="internal_error",
                    message="An unexpected error occurred.",
                    request_id=rid,
                )
            ),
        )
