"""
Structured errors for the CTI Command Center Python tooling.

Every exception carries a ``context`` dict for logging and diagnostics.
"""

from __future__ import annotations

from typing import TypeAlias

__all__ = (
    "CriticalConfigError",
    "CrispyError",
    "DependencyUnavailableError",
    "InternalLogicError",
    "JsonValue",
    "NetworkError",
    "ValidationError",
)

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class CrispyError(Exception):
    """Base error with mandatory ``context`` metadata."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        if not isinstance(context, dict):
            raise TypeError("context must be a dict")
        self.context = dict(context)
        msg = message if message is not None else self._default_message()
        super().__init__(msg)

    def _default_message(self) -> str:
        return type(self).__name__


class NetworkError(CrispyError):
    """Connectivity, HTTP transport, or remote API failures."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        super().__init__(context, message=message)


class ValidationError(CrispyError):
    """Invalid input, missing configuration, or schema violations."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        super().__init__(context, message=message)


class CriticalConfigError(CrispyError):
    """Required configuration missing or invalid; the process should exit without recovery."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        super().__init__(context, message=message)


class DependencyUnavailableError(CrispyError):
    """Upstream service rejected by circuit breaker (cooldown / overload)."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        super().__init__(context, message=message)


class InternalLogicError(CrispyError):
    """Bug, impossible state, or missing optional dependency when required."""

    def __init__(self, context: dict[str, JsonValue], *, message: str | None = None) -> None:
        super().__init__(context, message=message)
