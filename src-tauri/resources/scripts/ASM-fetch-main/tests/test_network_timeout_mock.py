"""
Network-dependent paths: exercise timeout / retry / error handling with realistic ``requests`` shapes.

Uses :class:`requests.Response` objects (see ``http_mock_helpers``) for success and HTTP error
statuses, and :mod:`requests.exceptions` for transport failures (read timeout, connection reset),
instead of ``MagicMock().json.return_value = {static dict}``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

import src.api.pentest_tools as pentest_tools
from src.api.pentest_tools import get_pentest_subdomains
from src.endpoint import dns as dns_module
from tests.http_mock_helpers import (
    connection_reset_request_exception,
    json_http_response,
    pentest_scan_created_response,
    pentest_scan_status_running_response,
    rate_limited_response,
    unauthorized_response,
)

pytestmark = pytest.mark.network


@pytest.fixture
def mock_circuit_identity():
    """Run protected call inline so tests control HTTP without registry side effects."""

    def _run(name: str, fn):
        return fn()

    with patch("src.endpoint.dns.circuit_protect", side_effect=_run):
        with patch("src.api.pentest_tools.circuit_protect", side_effect=_run):
            yield


def test_dns_post_uses_ten_second_timeout_kwarg(mock_circuit_identity) -> None:
    """RapidAPI DNS call passes ``timeout=10`` to ``requests.post``."""
    captured: dict = {}

    def _post(*args, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        raise requests.exceptions.ReadTimeout("simulated read timeout after stall")

    with patch.object(dns_module.requests, "post", side_effect=_post):
        dns_module.query_dns_record(
            "example.com",
            "MX",
            rapidapi_key="test-key-12345678901234567890",
            max_retries=1,
            backoff=2,
        )

    assert captured.get("timeout") == 10


def test_dns_retries_bounded_on_timeout_no_infinite_loop(mock_circuit_identity) -> None:
    """
    Each attempt raises ``ReadTimeout`` (simulated network stall beyond HTTP timeout).
    Retry loop and backoff must finish in a bounded number of iterations — no hang.
    """
    sleep_calls: list[float] = []

    def _post(*args, **kwargs):
        raise requests.exceptions.ReadTimeout("simulated timeout")

    def record_sleep(s: float) -> None:
        sleep_calls.append(float(s))

    with patch.object(dns_module.requests, "post", side_effect=_post):
        with patch.object(dns_module.time, "sleep", side_effect=record_sleep):
            dns_module.query_dns_record(
                "example.com",
                "MX",
                rapidapi_key="test-key-12345678901234567890",
                max_retries=3,
                backoff=2,
            )

    assert len(sleep_calls) == 3
    assert sleep_calls == [1.0, 2.0, 4.0]


def test_dns_unauthorized_401_exhausts_retries(mock_circuit_identity) -> None:
    """API returns 401: ``raise_for_status`` fails each time; no static success JSON path."""
    sleep_calls: list[float] = []

    def record_sleep(s: float) -> None:
        sleep_calls.append(float(s))

    with patch.object(
        dns_module.requests,
        "post",
        return_value=unauthorized_response(),
    ):
        with patch.object(dns_module.time, "sleep", side_effect=record_sleep):
            out = dns_module.query_dns_record(
                "example.com",
                "MX",
                rapidapi_key="test-key-12345678901234567890",
                max_retries=2,
                backoff=2,
            )

    assert out["success"] is False
    assert out["records"] == []
    assert len(sleep_calls) == 2


def test_dns_rate_limited_429_exhausts_retries(mock_circuit_identity) -> None:
    """429 + ``Retry-After`` still surfaces as failed ``raise_for_status`` until retries end."""
    sleep_calls: list[float] = []

    def record_sleep(s: float) -> None:
        sleep_calls.append(float(s))

    with patch.object(
        dns_module.requests,
        "post",
        return_value=rate_limited_response(retry_after_s=30),
    ):
        with patch.object(dns_module.time, "sleep", side_effect=record_sleep):
            out = dns_module.query_dns_record(
                "example.com",
                "MX",
                rapidapi_key="test-key-12345678901234567890",
                max_retries=2,
                backoff=2,
            )

    assert out["success"] is False
    assert out["records"] == []
    assert len(sleep_calls) == 2


def test_dns_connection_reset_respected_as_request_exception(mock_circuit_identity) -> None:
    """Transport reset (``ECONNRESET``) is a ``RequestException``; same retry contract as timeouts."""
    sleep_calls: list[float] = []

    def record_sleep(s: float) -> None:
        sleep_calls.append(float(s))

    with patch.object(
        dns_module.requests,
        "post",
        side_effect=connection_reset_request_exception,
    ):
        with patch.object(dns_module.time, "sleep", side_effect=record_sleep):
            dns_module.query_dns_record(
                "example.com",
                "MX",
                rapidapi_key="test-key-12345678901234567890",
                max_retries=2,
                backoff=2,
            )

    assert len(sleep_calls) == 2


def test_pentest_poll_respects_total_timeout_with_simulated_delays(mock_circuit_identity) -> None:
    """
    Simulate elapsed time advancing by 2s per poll (``time.sleep(2)`` in production).

    After enough simulated time, ``while time.time() - started < timeout`` must fail
    even if the scan never completes — exit without infinite polling.

    ``requests`` returns real JSON HTTP 200 bodies for start + running poll.
    """
    clock = {"t": 0.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_sleep(seconds: float) -> None:
        clock["t"] += seconds

    with patch.object(
        pentest_tools.requests,
        "post",
        return_value=pentest_scan_created_response(scan_id="scan-1"),
    ):
        with patch.object(
            pentest_tools.requests,
            "get",
            return_value=pentest_scan_status_running_response(),
        ):
            with patch.object(pentest_tools.time, "time", side_effect=fake_time):
                with patch.object(pentest_tools.time, "sleep", side_effect=fake_sleep):
                    out = get_pentest_subdomains(
                        "example.com",
                        token="bearer-token-placeholder",
                        timeout=10,
                    )

    assert out == []
    assert clock["t"] >= 10.0, "simulated clock must reach total timeout budget"
    assert clock["t"] < 200.0, "must not spin until absurd simulated time (no infinite loop)"


def test_pentest_simulated_ten_second_per_request_stall_raises_timeout(mock_circuit_identity) -> None:
    """
    Per-request stall surfaces as ``ReadTimeout``; handler must not loop forever.

    Start scan still returns a normal 200 + JSON body (real :class:`requests.Response`).
    """
    clock = {"t": 0.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_sleep(seconds: float) -> None:
        clock["t"] += seconds

    def poll_get(_url, **kwargs):
        assert kwargs.get("timeout") == 15
        raise requests.exceptions.ReadTimeout(
            "simulated 10s stall capped by requests timeout"
        )

    with patch.object(
        pentest_tools.requests,
        "post",
        return_value=pentest_scan_created_response(scan_id="scan-2"),
    ):
        with patch.object(pentest_tools.requests, "get", side_effect=poll_get):
            with patch.object(pentest_tools.time, "time", side_effect=fake_time):
                with patch.object(pentest_tools.time, "sleep", side_effect=fake_sleep):
                    out = get_pentest_subdomains(
                        "example.com",
                        token="tok",
                        timeout=12,
                    )

    assert out == []
    assert clock["t"] >= 12.0


def test_pentest_start_scan_401_returns_empty(mock_circuit_identity) -> None:
    """401 Unauthorized on scan start — ``raise_for_status`` aborts; caller yields empty list."""
    with patch.object(pentest_tools.requests, "post", return_value=unauthorized_response()):
        out = get_pentest_subdomains("example.com", token="bad-token", timeout=60)

    assert out == []


def test_pentest_start_scan_429_returns_empty(mock_circuit_identity) -> None:
    """429 + JSON error body (rate limit) on start — same early exit as live API throttling."""
    with patch.object(
        pentest_tools.requests,
        "post",
        return_value=rate_limited_response(retry_after_s=120),
    ):
        out = get_pentest_subdomains("example.com", token="tok", timeout=60)

    assert out == []


def test_pentest_start_scan_connection_reset_returns_empty(mock_circuit_identity) -> None:
    """Connection reset on ``POST /scans`` (no HTTP response) — connection error path."""
    with patch.object(
        pentest_tools.requests,
        "post",
        side_effect=connection_reset_request_exception,
    ):
        out = get_pentest_subdomains("example.com", token="tok", timeout=60)

    assert out == []


def test_pentest_poll_401_after_start_stops_with_empty_result(mock_circuit_identity) -> None:
    """Scan starts OK; first poll returns 401 (token revoked mid-flight)."""
    clock = {"t": 0.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_sleep(seconds: float) -> None:
        clock["t"] += seconds

    with patch.object(
        pentest_tools.requests,
        "post",
        return_value=pentest_scan_created_response(scan_id="scan-mid"),
    ):
        with patch.object(pentest_tools.requests, "get", return_value=unauthorized_response()):
            with patch.object(pentest_tools.time, "time", side_effect=fake_time):
                with patch.object(pentest_tools.time, "sleep", side_effect=fake_sleep):
                    out = get_pentest_subdomains(
                        "example.com",
                        token="tok",
                        timeout=300,
                    )

    assert out == []


def test_json_http_response_helpers_roundtrip() -> None:
    """Sanity: helpers produce responses compatible with ``raise_for_status`` / ``json()``."""
    ok = json_http_response(status_code=200, json_body={"data": {"created_id": "x"}})
    ok.raise_for_status()
    assert ok.json()["data"]["created_id"] == "x"

    bad = unauthorized_response()
    with pytest.raises(requests.HTTPError):
        bad.raise_for_status()
