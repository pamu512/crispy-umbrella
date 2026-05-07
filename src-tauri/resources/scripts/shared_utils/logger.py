"""
Centralized JSON logging to stdout.

Call :func:`configure_logging` once at process startup.

**Correlation IDs:** :class:`CorrelationIdFilter` injects ``correlation_id`` into every
:class:`~logging.LogRecord` from a :class:`contextvars.ContextVar`, so log formatters
never need manual string formatting. For HTTP, bind the context in middleware (see ASM
``RequestIdMiddleware``) or use :func:`correlation_scope` elsewhere.

**Audit:** level :data:`AUDIT` (25, between INFO and WARNING). Use :func:`audit_state_change`
for compliance-style state transitions; these lines include ``log_kind: "audit"`` and
structured ``audit_*`` fields, distinct from DEBUG/INFO operational logs.

Every emitted record includes: timestamp (ISO 8601 UTC), level, module, function,
line_number, correlation_id, and message.
"""

from __future__ import annotations

import enum
import json
import logging
import sys
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import IO, Iterator

# Between INFO (20) and WARNING (30): enables when root level is INFO, filterable separately.
AUDIT = 25

__all__ = (
    "AUDIT",
    "CorrelationIdFilter",
    "audit_state_change",
    "configure_logging",
    "correlation_scope",
    "get_correlation_id",
    "logging_health_ok",
    "register_audit_level",
    "reset_correlation_id",
    "set_correlation_id",
)


def register_audit_level() -> None:
    """Register the ``AUDIT`` level name with :mod:`logging` (idempotent)."""
    if logging.getLevelName(AUDIT) != "AUDIT":
        logging.addLevelName(AUDIT, "AUDIT")


def _audit_repr(value: object) -> str:
    if isinstance(value, enum.Enum):
        return str(value.value)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except TypeError:
        return repr(value)


def audit_state_change(
    logger: logging.Logger,
    *,
    component: str,
    previous_state: object,
    new_state: object,
    detail: str | None = None,
) -> None:
    """
    Emit an AUDIT record for a logical state transition.

    ``component`` identifies the triggering subsystem (e.g. ``ingestor.CSVIngestor``).
    Message text is derived automatically; do not encode state in ad-hoc INFO strings.
    """
    register_audit_level()
    prev_s = _audit_repr(previous_state)
    new_s = _audit_repr(new_state)
    msg = f"State changed from {prev_s} to {new_s}"
    extra: dict[str, str] = {
        "audit_event": "state_change",
        "audit_component": component,
        "audit_previous_state": prev_s,
        "audit_new_state": new_s,
    }
    if detail:
        extra["audit_detail"] = detail
    # Attribute the record to the caller (ingestor, db_manager, …), not this helper.
    logger.log(AUDIT, msg, extra=extra, stacklevel=2)


register_audit_level()

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    return _correlation_id.get()


def set_correlation_id(value: str) -> Token[str]:
    return _correlation_id.set(value)


def reset_correlation_id(token: Token[str]) -> None:
    _correlation_id.reset(token)


@contextmanager
def correlation_scope(correlation_id: str) -> Iterator[None]:
    """Bind ``correlation_id`` for the current async task / thread for the block."""
    token = set_correlation_id(correlation_id)
    try:
        yield
    finally:
        reset_correlation_id(token)


class CorrelationIdFilter(logging.Filter):
    """
    Copy the contextual correlation id onto each :class:`~logging.LogRecord`.

    Runs before formatters so every log line can include ``correlation_id`` without
    embedding it in the message string.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = get_correlation_id()
        return True


def _utc_iso8601(record: logging.LogRecord) -> str:
    dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


class JsonStdoutFormatter(logging.Formatter):
    """Serialize log records as single-line JSON on stdout."""

    def format(self, record: logging.LogRecord) -> str:
        cid = getattr(record, "correlation_id", get_correlation_id())
        payload: dict[str, object] = {
            "timestamp": _utc_iso8601(record),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line_number": record.lineno,
            "correlation_id": cid,
            "message": record.getMessage(),
        }
        if record.levelno == AUDIT or getattr(record, "audit_event", None):
            payload["log_kind"] = "audit"
            for key in (
                "audit_event",
                "audit_component",
                "audit_previous_state",
                "audit_new_state",
                "audit_detail",
            ):
                if hasattr(record, key):
                    payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class JsonStdoutHandler(logging.StreamHandler[IO[str]]):
    """Write JSON log lines to stdout (not stderr)."""

    def __init__(self) -> None:
        super().__init__(sys.stdout)


_configured = False


def _remove_json_stdout_handlers_for_force(root: logging.Logger) -> None:
    root.handlers[:] = [
        h
        for h in root.handlers
        if not (isinstance(h, JsonStdoutHandler) and h.stream is sys.stdout)
    ]


def _reuse_existing_json_stdout_handler(root: logging.Logger) -> bool:
    for h in root.handlers:
        if isinstance(h, JsonStdoutHandler) and getattr(h, "stream", None) is sys.stdout:
            if not any(isinstance(f, CorrelationIdFilter) for f in h.filters):
                h.addFilter(CorrelationIdFilter())
            return True
    return False


def _attach_new_json_stdout_handler(root: logging.Logger) -> None:
    handler = JsonStdoutHandler()
    handler.addFilter(CorrelationIdFilter())
    handler.setFormatter(JsonStdoutFormatter())
    root.addHandler(handler)


def configure_logging(
    level: int = logging.INFO,
    *,
    force: bool = False,
) -> None:
    """
    Attach a JSON :class:`JsonStdoutHandler` to the root logger.

    Idempotent unless ``force=True`` (removes prior JSON stdout handlers and re-attaches).
    """
    global _configured
    register_audit_level()
    root = logging.getLogger()
    root.setLevel(level)

    if force:
        _remove_json_stdout_handlers_for_force(root)
        _configured = False

    if _configured and not force:
        return

    if _reuse_existing_json_stdout_handler(root):
        _configured = True
        return

    _attach_new_json_stdout_handler(root)
    _configured = True


def logging_health_ok() -> tuple[bool, str]:
    """
    Return whether centralized JSON logging is configured on the root logger.

    Used by health checks: expects :class:`JsonStdoutHandler` on the root logger
    (as installed by :func:`configure_logging`).
    """
    root = logging.getLogger()
    if not root.handlers:
        return False, "root logger has no handlers"
    has_json_stdout = any(
        isinstance(h, JsonStdoutHandler) and getattr(h, "stream", None) is sys.stdout
        for h in root.handlers
    )
    if not has_json_stdout:
        return False, "centralized JsonStdoutHandler not attached to root logger"
    if not root.isEnabledFor(logging.INFO):
        return False, "root logger level suppresses INFO"
    return True, "logging subsystem active"
