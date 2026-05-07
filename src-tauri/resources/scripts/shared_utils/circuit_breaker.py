"""
Thread-safe circuit breaker for third-party dependencies.

Opens after ``failure_threshold`` failures within ``window_seconds``; while open,
:callers get :class:`exceptions.DependencyUnavailableError` until ``cooldown_seconds`` elapses.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

for _repo in Path(__file__).resolve().parents:
    if (_repo / "exceptions.py").is_file():
        if str(_repo) not in sys.path:
            sys.path.insert(0, str(_repo))
        break
else:
    raise ImportError("exceptions.py not found from circuit_breaker.py")

from exceptions import DependencyUnavailableError, JsonValue

T = TypeVar("T")

__all__ = (
    "CircuitBreaker",
    "DependencyUnavailableError",
    "circuit_protect",
    "circuit_registry_snapshot",
    "get_breaker",
)

_registry: dict[str, "CircuitBreaker"] = {}
_registry_lock = threading.Lock()


class CircuitBreaker:
    """
    Counts failures in a sliding window. Opens the circuit when the threshold is reached,
    then blocks with :class:`DependencyUnavailableError` until cooldown expires.
    """

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._fail_times: list[float] = []
        self._open_until: float | None = None
        self._lock = threading.Lock()

    def _purge_old(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._fail_times = [t for t in self._fail_times if t >= cutoff]

    def protect(self, fn: Callable[[], T]) -> T:
        """Run ``fn`` when the circuit allows; record failures and successes."""
        with self._lock:
            now = time.monotonic()
            self._purge_old(now)
            if self._open_until is not None:
                if now < self._open_until:
                    raise DependencyUnavailableError(
                        {
                            "dependency": self.name,
                            "reason": "circuit_open",
                            "cooldown_remaining_s": round(self._open_until - now, 3),
                        },
                        message=(
                            f"Dependency {self.name!r} is temporarily unavailable "
                            "(circuit open; cooldown active)"
                        ),
                    )
                self._open_until = None
                self._fail_times.clear()

        try:
            out = fn()
        except Exception:
            with self._lock:
                now = time.monotonic()
                self._fail_times.append(now)
                self._purge_old(now)
                if len(self._fail_times) >= self.failure_threshold:
                    self._open_until = now + self.cooldown_seconds
            raise
        else:
            with self._lock:
                self._fail_times.clear()
                self._open_until = None
            return out

    def snapshot(self) -> dict[str, JsonValue]:
        """Current window failure count, whether the circuit is open, and cooldown (debug dashboards)."""
        with self._lock:
            now = time.monotonic()
            self._purge_old(now)
            open_until = self._open_until
            cool = 0.0
            if open_until is not None:
                rem = open_until - now
                if rem > 0:
                    cool = round(rem, 3)
            circuit_open = open_until is not None and now < open_until
            return {
                "failure_count_window": len(self._fail_times),
                "circuit_open": circuit_open,
                "cooldown_remaining_s": cool,
                "failure_threshold": self.failure_threshold,
                "window_seconds": self.window_seconds,
            }


def get_breaker(name: str) -> CircuitBreaker:
    """Return a shared :class:`CircuitBreaker` instance for ``name``."""
    with _registry_lock:
        if name not in _registry:
            _registry[name] = CircuitBreaker(name)
        return _registry[name]


def circuit_registry_snapshot() -> dict[str, dict[str, JsonValue]]:
    """All named circuit breakers (cache / breaker registry size = number of keys)."""
    with _registry_lock:
        names = sorted(_registry.keys())
    return {n: get_breaker(n).snapshot() for n in names}


def circuit_protect(name: str, fn: Callable[[], T]) -> T:
    """Run ``fn`` behind the named circuit breaker."""
    return get_breaker(name).protect(fn)
