"""
Invalid-input tests for ``input_validation`` core utilities.

Each case uses ``None``, empty strings, extreme integers, or bytes (non-text)
and must raise :class:`exceptions.ValidationError`.
"""

from __future__ import annotations

import sys

import pytest

from exceptions import ValidationError
from input_validation import (
    validate_csv_file_path,
    validate_optional_project_folder,
    validate_optional_project_type,
    validate_optional_workspace_directory,
    validate_workspace_path_required,
)


def test_workspace_path_required_none_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_workspace_path_required(None, field="workspace")
    assert exc.value.context.get("reason") == "missing"


def test_workspace_path_required_empty_string_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_workspace_path_required("", field="workspace")
    assert exc.value.context.get("reason") == "empty"


def test_workspace_path_required_max_int_raises() -> None:
    """Integer path (maximum-width ``sys.maxsize``) is an invalid type."""
    with pytest.raises(ValidationError) as exc:
        validate_workspace_path_required(sys.maxsize, field="workspace")
    assert exc.value.context.get("reason") == "type"
    assert exc.value.context.get("got") == "int"


def test_csv_file_path_empty_string_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_csv_file_path("", field="file")
    assert exc.value.context.get("reason") == "empty"


def test_csv_file_path_none_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_csv_file_path(None, field="file")  # type: ignore[arg-type]
    assert exc.value.context.get("reason") == "type"


def test_csv_file_path_bytes_non_text_raises() -> None:
    """Bytes path is invalid (not ``str`` / ``Path``); models mis-encoded / binary input."""
    raw = b"/tmp/not-a-unicode-path.csv"
    with pytest.raises(ValidationError) as exc:
        validate_csv_file_path(raw, field="file")  # type: ignore[arg-type]
    assert exc.value.context.get("reason") == "type"
    assert exc.value.context.get("got") == "bytes"


def test_optional_workspace_bytes_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_optional_workspace_directory(b"/workspace", field="CTI_WORKSPACE_PATH")  # type: ignore[arg-type]
    assert exc.value.context.get("reason") == "type"
    assert exc.value.context.get("got") == "bytes"


def test_optional_project_type_extreme_int_raises() -> None:
    """Very large integer must not be accepted as a project type token."""
    huge = 2**256 - 1
    with pytest.raises(ValidationError) as exc:
        validate_optional_project_type(huge, field="project_type")  # type: ignore[arg-type]
    assert exc.value.context.get("reason") == "type"
    assert exc.value.context.get("got") == "int"


def test_optional_project_folder_empty_string_raises() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_optional_project_folder("", field="project_folder")
    assert exc.value.context.get("reason") == "empty_not_allowed"


def test_optional_project_folder_none_like_bytes_raises() -> None:
    """Bytes are not valid folder names (non-UTF-8 text channel)."""
    with pytest.raises(ValidationError) as exc:
        validate_optional_project_folder(b"Intelx_Crawler", field="project_folder")  # type: ignore[arg-type]
    assert exc.value.context.get("reason") == "type"
    assert exc.value.context.get("got") == "bytes"
