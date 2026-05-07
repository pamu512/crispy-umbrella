"""Unit tests for cooperative SIGINT/SIGTERM flag (no real signals required)."""

from __future__ import annotations

from graceful_shutdown import (
    install_handlers,
    request_shutdown,
    reset_shutdown_flag_for_tests,
    shutdown_requested,
)


def test_request_and_reset_flag() -> None:
    reset_shutdown_flag_for_tests()
    assert not shutdown_requested()
    request_shutdown()
    assert shutdown_requested()
    reset_shutdown_flag_for_tests()
    assert not shutdown_requested()


def test_install_handlers_idempotent() -> None:
    assert install_handlers() is True
    assert install_handlers() is True
