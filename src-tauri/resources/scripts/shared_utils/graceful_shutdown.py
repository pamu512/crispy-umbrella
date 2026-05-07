"""
Cooperative shutdown on SIGINT / SIGTERM.

Handlers only set a flag (signal-safe). Long-running work checks :func:`shutdown_requested`
between logical tasks so the current task finishes, then callers close resources (e.g.
:class:`~db_manager.CTIVault` context managers) and exit with code ``0``.
"""

from __future__ import annotations

import signal
import threading

_event = threading.Event()
_handlers_installed: bool = False


def shutdown_requested() -> bool:
    return _event.is_set()


def request_shutdown() -> None:
    """Programmatically request shutdown (same effect as SIGINT/SIGTERM after install)."""
    _event.set()


def reset_shutdown_flag_for_tests() -> None:
    """Clear the shutdown flag (tests only). Does not uninstall OS handlers."""
    _event.clear()


def install_handlers() -> bool:
    """
    Install SIGINT and SIGTERM handlers that set the shutdown flag.

    Must run on the main thread (required by :func:`signal.signal`). Safe to call multiple times;
    installs only once. Returns ``False`` if installation failed (e.g. wrong thread).
    """
    global _handlers_installed
    if _handlers_installed:
        return True

    def _handle(signum: int, frame: object | None) -> None:  # noqa: ARG001
        del frame  # unused; required by signal handler signature
        _event.set()

    try:
        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)
    except ValueError:
        return False
    _handlers_installed = True
    return True
