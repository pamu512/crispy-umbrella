"""
Threshold-based timing for primary logic blocks.

Logs duration in milliseconds only when execution exceeds the configured threshold
(default 500 ms).
"""

from __future__ import annotations

import logging
import time
import types

DEFAULT_THRESHOLD_MS = 500.0

__all__ = ("DEFAULT_THRESHOLD_MS", "time_execution")


class time_execution:
    """
    Measure wall time for the wrapped block using :func:`time.perf_counter`.

    Emits a single log line with duration in **milliseconds** only if the elapsed time
    strictly exceeds ``threshold_ms``.

    Use as ``with time_execution(logger, label=\"...\"):`` — the class is named
    :class:`time_execution` per project convention.
    """

    __slots__ = ("_level", "_logger", "_start", "_threshold_ms", "label")

    def __init__(
        self,
        logger: logging.Logger,
        *,
        label: str,
        threshold_ms: float = DEFAULT_THRESHOLD_MS,
        level: int = logging.INFO,
    ) -> None:
        self._logger = logger
        self.label = label
        self._threshold_ms = threshold_ms
        self._level = level
        self._start = 0.0

    def __enter__(self) -> time_execution:
        self._start = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        elapsed_ms = (time.perf_counter() - self._start) * 1000.0
        if elapsed_ms > self._threshold_ms:
            self._logger.log(
                self._level,
                "%s duration_ms=%.2f (threshold_ms=%.0f)",
                self.label,
                elapsed_ms,
                self._threshold_ms,
                stacklevel=2,
            )
