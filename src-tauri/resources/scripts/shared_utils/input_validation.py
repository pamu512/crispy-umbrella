"""
Strict validation for externally supplied paths and CLI/API strings.

Raises ``exceptions.ValidationError`` (repo root); does not silently normalize inputs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal, cast

_LitCVEIOCASM = Literal["CVE", "IOC", "ASM"]

for _repo in Path(__file__).resolve().parents:
    if (_repo / "exceptions.py").is_file():
        if str(_repo) not in sys.path:
            sys.path.insert(0, str(_repo))
        break
else:
    raise ImportError("exceptions.py not found on path ancestors of input_validation.py")

from constants import BUNDLED_PROJECT_FOLDER_NAMES, ENV_CTI_WORKSPACE_PATH
from exceptions import JsonValue, ValidationError

__all__ = (
    "ALLOWED_PROJECT_FOLDERS",
    "ALLOWED_PROJECT_TYPES",
    "ValidationError",
    "validate_csv_file_path",
    "validate_optional_project_folder",
    "validate_optional_project_type",
    "validate_optional_workspace_directory",
    "validate_workspace_path_required",
)

ALLOWED_PROJECT_FOLDERS: frozenset[str] = frozenset(BUNDLED_PROJECT_FOLDER_NAMES)

ALLOWED_PROJECT_TYPES: frozenset[str] = frozenset(("CVE", "IOC", "ASM"))


def validate_workspace_path_required(raw: str | None, *, field: str = "workspace") -> Path:
    """Workspace root must be a non-empty string path to an existing directory (no padding)."""
    if raw is None:
        raise ValidationError(
            {field: raw, "reason": "missing"},
            message=f"{field} is required (non-empty string path)",
        )
    if not isinstance(raw, str):
        raise ValidationError(
            {field: raw, "reason": "type", "got": type(raw).__name__},
            message=f"{field} must be a string path",
        )
    if raw != raw.strip():
        raise ValidationError(
            {field: raw, "reason": "surrounding_whitespace"},
            message=f"{field} must not have leading or trailing whitespace",
        )
    if raw == "":
        raise ValidationError(
            {field: raw, "reason": "empty"},
            message=f"{field} must not be empty",
        )
    try:
        p = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as e:
        raise ValidationError(
            {field: raw, "reason": "path_resolve", "detail": str(e)},
            message=f"{field} is not a valid filesystem path",
        ) from e
    if not p.is_dir():
        raise ValidationError(
            {field: str(p), "reason": "not_a_directory"},
            message=f"{field} must refer to an existing directory",
        )
    return p


def validate_optional_workspace_directory(
    raw: str | None,
    *,
    field: str = ENV_CTI_WORKSPACE_PATH,
) -> Path | None:
    """Optional workspace from env: unset/None → None; otherwise same rules as required (must exist)."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValidationError(
            {field: raw, "reason": "type", "got": type(raw).__name__},
            message=f"{field} must be a string when set",
        )
    if raw != raw.strip():
        raise ValidationError(
            {field: raw, "reason": "surrounding_whitespace"},
            message=f"{field} must not have leading or trailing whitespace",
        )
    if raw == "":
        return None
    try:
        p = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as e:
        raise ValidationError(
            {field: raw, "reason": "path_resolve", "detail": str(e)},
            message=f"{field} is not a valid filesystem path",
        ) from e
    if not p.is_dir():
        raise ValidationError(
            {field: str(p), "reason": "not_a_directory"},
            message=f"{field} must refer to an existing directory when set",
        )
    return p


def validate_csv_file_path(raw: str | Path, *, field: str = "file") -> Path:
    """CSV input must be a path to an existing regular file (no padding for str paths)."""
    if isinstance(raw, Path):
        try:
            p = raw.expanduser().resolve()
        except (OSError, RuntimeError, ValueError) as e:
            raise ValidationError(
                {field: str(raw), "reason": "path_resolve", "detail": str(e)},
                message=f"{field} is not a valid filesystem path",
            ) from e
        if not p.is_file():
            raise ValidationError(
                {field: str(p), "reason": "not_a_file"},
                message=f"{field} must be an existing regular file",
            )
        return p

    if not isinstance(raw, str):
        raise ValidationError(
            {field: raw, "reason": "type", "got": type(raw).__name__},
            message=f"{field} must be a string or pathlib.Path",
        )
    if raw != raw.strip():
        raise ValidationError(
            {field: raw, "reason": "surrounding_whitespace"},
            message=f"{field} must not have leading or trailing whitespace",
        )
    if raw == "":
        raise ValidationError(
            {field: raw, "reason": "empty"},
            message=f"{field} must not be empty",
        )
    try:
        p = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as e:
        raise ValidationError(
            {field: raw, "reason": "path_resolve", "detail": str(e)},
            message=f"{field} is not a valid filesystem path",
        ) from e
    if not p.is_file():
        raise ValidationError(
            {field: str(p), "reason": "not_a_file"},
            message=f"{field} must be an existing regular file",
        )
    return p


def validate_optional_project_type(
    raw: str | None,
    *,
    field: str = "project_type",
) -> _LitCVEIOCASM | None:
    """``CVE`` | ``IOC`` | ``ASM`` only; ``None`` allowed; no case folding."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValidationError(
            {field: raw, "reason": "type", "got": type(raw).__name__},
            message=f"{field} must be a string or omitted",
        )
    if raw != raw.strip():
        raise ValidationError(
            {field: raw, "reason": "surrounding_whitespace"},
            message=f"{field} must not have leading or trailing whitespace",
        )
    if raw == "":
        return None
    if raw not in ALLOWED_PROJECT_TYPES:
        raise ValidationError(
            {
                field: raw,
                "reason": "not_allowed",
                "allowed": cast(list[JsonValue], sorted(ALLOWED_PROJECT_TYPES)),
            },
            message=f"{field} must be one of {sorted(ALLOWED_PROJECT_TYPES)}",
        )
    return cast(_LitCVEIOCASM, raw)


def validate_optional_project_folder(
    raw: str | None,
    *,
    field: str = "project_folder",
) -> str | None:
    """Bundled folder name only; ``None`` allowed; empty string is invalid."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValidationError(
            {field: raw, "reason": "type", "got": type(raw).__name__},
            message=f"{field} must be a string or omitted",
        )
    if raw != raw.strip():
        raise ValidationError(
            {field: raw, "reason": "surrounding_whitespace"},
            message=f"{field} must not have leading or trailing whitespace",
        )
    if raw == "":
        raise ValidationError(
            {field: raw, "reason": "empty_not_allowed"},
            message=f"{field} cannot be empty; omit the argument instead",
        )
    if raw not in ALLOWED_PROJECT_FOLDERS:
        raise ValidationError(
            {
                field: raw,
                "reason": "not_allowed",
                "allowed": cast(list[JsonValue], sorted(ALLOWED_PROJECT_FOLDERS)),
            },
            message=f"{field} must be one of the bundled project folder names",
        )
    return raw
