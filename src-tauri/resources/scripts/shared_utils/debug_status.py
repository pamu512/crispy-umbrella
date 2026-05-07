"""
Internal ``/status``-style snapshot for Python sidecars: circuit breaker registry and counters.

Logs a single compact JSON line at INFO (message prefix ``cti.status``) for log aggregators;
use :func:`collect_python_debug_snapshot` to read the same data without logging.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from circuit_breaker import circuit_registry_snapshot
from versioned_export import with_export_version

_LOG = logging.getLogger(__name__)


def collect_python_debug_snapshot() -> dict[str, Any]:
    """Return circuit breaker state; registry size equals number of named breakers used so far."""
    br = circuit_registry_snapshot()
    return with_export_version(
        {
            "circuit_breaker_names": sorted(br.keys()),
            "circuit_breakers": br,
        }
    )


def log_internal_status(logger: logging.Logger | None = None) -> dict[str, Any]:
    """
    Emit one JSON line (sorted keys, compact separators) and return the payload.

    Filter logs by ``cti.status`` or the logger name to isolate dashboard noise.
    """
    payload = collect_python_debug_snapshot()
    log = logger or _LOG
    log.info(
        "cti.status %s",
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
    )
    return payload
