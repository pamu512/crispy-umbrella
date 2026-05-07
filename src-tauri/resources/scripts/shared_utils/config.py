"""
Class-based environment configuration for CTI Python tooling.

Environment variables are read once and cast to concrete types. Callers that run under the
Tauri host (or any sidecar) should pass ``required`` for variables that must be present::

    from config import CtiAppConfig, SIDEcar_REQUIRED

    cfg = CtiAppConfig.from_environ(required=SIDEcar_REQUIRED)

Use :func:`load_or_exit` at process startup when a missing variable should terminate the app.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from constants import (
    DEFAULT_CTI_APP_IDENTIFIER,
    ENV_CTI_APP_DATA_ROOT,
    ENV_CTI_APP_IDENTIFIER,
    ENV_CTI_DB_PATH,
    ENV_CTI_HTTP_TIMEOUT_SECONDS,
    ENV_CTI_LOGS_DIR,
    ENV_CTI_NON_INTERACTIVE,
    ENV_CTI_WRITABLE_ROOT,
    ENV_CTI_WORKSPACE_PATH,
)

for _cfg_root in Path(__file__).resolve().parents:
    if (_cfg_root / "exceptions.py").is_file():
        if str(_cfg_root) not in sys.path:
            sys.path.insert(0, str(_cfg_root))
        from exceptions import CriticalConfigError, JsonValue

        break
else:  # pragma: no cover
    raise ImportError("exceptions.py not found; cannot load CriticalConfigError")

# Minimum env vars expected when spawned by the Tauri host with a resolved vault path.
SIDEcar_REQUIRED: frozenset[str] = frozenset({ENV_CTI_DB_PATH})

_TRUEISH: Final[frozenset[str]] = frozenset(
    ("1", "true", "yes", "y", "on"),
)
_FALSEISH: Final[frozenset[str]] = frozenset(
    ("0", "false", "no", "n", "off", ""),
)


def _strip_env(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    s = str(raw).strip()
    return s if s else None


def _require_present(names: frozenset[str]) -> None:
    missing: list[str] = []
    for name in sorted(names):
        if _strip_env(name) is None:
            missing.append(name)
    if missing:
        raise CriticalConfigError(
            {"missing": missing, "reason": "required_env_unset"},
            message=f"Missing or empty required environment variable(s): {', '.join(missing)}",
        )


def _parse_bool(raw: str | None, *, default: bool, var: str) -> bool:
    if raw is None:
        return default
    s = raw.strip().lower()
    if s in _TRUEISH:
        return True
    if s in _FALSEISH:
        return False
    raise CriticalConfigError(
        {"var": var, "value": raw, "reason": "invalid_bool"},
        message=f"Invalid boolean for {var!r}: expected true/false/1/0/yes/no, got {raw!r}",
    )


def _parse_opt_path(name: str) -> Path | None:
    s = _strip_env(name)
    if s is None:
        return None
    return Path(s).expanduser()


def _parse_opt_non_negative_int(name: str) -> int | None:
    s = _strip_env(name)
    if s is None:
        return None
    try:
        n = int(s, 10)
    except ValueError as e:
        raise CriticalConfigError(
            {"var": name, "value": s, "reason": "invalid_int"},
            message=f"Invalid integer for {name!r}: {s!r}",
        ) from e
    if n < 0:
        raise CriticalConfigError(
            {"var": name, "value": n, "reason": "negative_int"},
            message=f"Environment variable {name!r} must be non-negative, got {n}",
        )
    return n


@dataclass(frozen=True, slots=True)
class CtiAppConfig:
    """Typed CTI settings from the process environment."""

    cti_db_path: Path | None
    cti_workspace_path: Path | None
    cti_logs_dir: Path | None
    cti_writable_root: Path | None
    cti_app_data_root: Path | None
    cti_app_identifier: str
    cti_non_interactive: bool
    http_timeout_seconds: int | None

    @classmethod
    def from_environ(
        cls,
        *,
        required: frozenset[str] | None = None,
    ) -> CtiAppConfig:
        """
        Load configuration from :func:`os.environ`.

        ``required`` names must be set to a non-empty string after stripping.
        """
        req = required if required is not None else frozenset()
        _require_present(req)

        ident_raw = _strip_env(ENV_CTI_APP_IDENTIFIER)
        non_interactive_raw = _strip_env(ENV_CTI_NON_INTERACTIVE)

        return cls(
            cti_db_path=_parse_opt_path(ENV_CTI_DB_PATH),
            cti_workspace_path=_parse_opt_path(ENV_CTI_WORKSPACE_PATH),
            cti_logs_dir=_parse_opt_path(ENV_CTI_LOGS_DIR),
            cti_writable_root=_parse_opt_path(ENV_CTI_WRITABLE_ROOT),
            cti_app_data_root=_parse_opt_path(ENV_CTI_APP_DATA_ROOT),
            cti_app_identifier=ident_raw or DEFAULT_CTI_APP_IDENTIFIER,
            cti_non_interactive=_parse_bool(
                non_interactive_raw, default=False, var=ENV_CTI_NON_INTERACTIVE
            ),
            http_timeout_seconds=_parse_opt_non_negative_int(ENV_CTI_HTTP_TIMEOUT_SECONDS),
        )


def load_or_exit(
    *,
    required: frozenset[str] | None = None,
    stream: object | None = None,
    code: int = 1,
) -> CtiAppConfig:
    """
    Load :class:`CtiAppConfig` or print the error and terminate the process.

    Use at application entry points when misconfiguration must be fatal.
    """
    err = stream if stream is not None else sys.stderr
    try:
        return CtiAppConfig.from_environ(required=required)
    except CriticalConfigError as e:
        print(str(e), file=err)
        ctx: dict[str, JsonValue] = dict(e.context)
        if ctx:
            parts = [f"{k}={v!r}" for k, v in sorted(ctx.items())]
            print("context: " + "; ".join(parts), file=err)
        raise SystemExit(code) from e
