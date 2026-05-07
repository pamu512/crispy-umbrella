"""
Realistic HTTP test doubles for ``requests`` (not bare ``MagicMock().json.return_value = {...}``).

Uses actual :class:`requests.Response` instances with status codes, bodies, and headers so
``raise_for_status()``, ``.json()``, and header reads behave like production traffic.
"""

from __future__ import annotations

import errno
import json
from typing import Any

import requests


def json_http_response(
    *,
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> requests.Response:
    """Build a :class:`~requests.Response` whose ``.json()`` decodes like a live API."""
    r = requests.Response()
    r.status_code = int(status_code)
    r.encoding = "utf-8"
    payload = json_body if json_body is not None else {}
    r._content = json.dumps(payload).encode("utf-8")  # noqa: SLF001
    r.headers["Content-Type"] = "application/json; charset=utf-8"
    return r


def pentest_scan_created_response(*, scan_id: str) -> requests.Response:
    """Successful Pentest-Tools ``POST /scans`` (Subdomain Finder start)."""
    return json_http_response(
        status_code=200,
        json_body={"data": {"created_id": scan_id}},
    )


def pentest_scan_status_running_response() -> requests.Response:
    """Poll response while the scan worker is still running."""
    return json_http_response(
        status_code=200,
        json_body={"data": {"status_name": "running"}},
    )


def unauthorized_response() -> requests.Response:
    """401 Unauthorized — invalid or expired bearer token."""
    return json_http_response(
        status_code=401,
        json_body={
            "error": "invalid_token",
            "error_description": "The access token is invalid or has expired",
        },
    )


def rate_limited_response(*, retry_after_s: int = 42) -> requests.Response:
    """429 Too Many Requests with ``Retry-After`` (seconds), as many APIs return."""
    r = json_http_response(
        status_code=429,
        json_body={
            "error": "rate_limit_exceeded",
            "message": "You have exceeded the maximum number of requests per minute.",
        },
    )
    r.headers["Retry-After"] = str(retry_after_s)
    return r


def connection_reset_request_exception(*_args: Any, **_kwargs: Any) -> None:
    """Simulate TCP ``ECONNRESET`` (peer closed connection) — common behind flaky proxies/CDNs."""
    err = OSError(errno.ECONNRESET, "Connection reset by peer")
    raise requests.exceptions.ConnectionError(err)
