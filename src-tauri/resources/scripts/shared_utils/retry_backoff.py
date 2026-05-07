"""
Retry transient failures with exponential backoff.

Used by ingest, HTTP clients, and browser automation helpers.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def with_exponential_backoff(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    base_delay_s: float = 1.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> T:
    """
    Run ``fn`` until it returns or retries are exhausted.

    Performs up to ``max_retries + 1`` attempts (one initial try plus ``max_retries``
    retries). After failure on attempt ``k`` (zero-based), waits
    ``base_delay_s * 2**k`` seconds before the next attempt.

    Re-raises the last caught exception if all attempts fail.
    """
    last_exc: BaseException | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt >= max_retries:
                raise
            time.sleep(base_delay_s * (2**attempt))
    assert last_exc is not None
    raise last_exc
