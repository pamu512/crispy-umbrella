"""
Fuzz / property-style stress test for the ``input_validation`` module.

Runs 1,000 pseudo-random inputs through every public validator. The module must never
raise a bare :class:`Exception` subclass outside the CTI **project error** hierarchy:
here :class:`exceptions.ValidationError` (subclass of :class:`exceptions.CrispyError`).
"""

from __future__ import annotations

import random
import string
import sys
from pathlib import Path
from typing import Any, Callable

# Mirror ``tests/conftest.py`` so ``python tests/test_fuzz_input_validation.py`` resolves imports.
_THIS_FILE = Path(__file__).resolve()
_SHARED_UTILS = _THIS_FILE.parents[1]
_REPO_ROOT = _THIS_FILE.parents[5]
for _p in (_SHARED_UTILS, _REPO_ROOT):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import pytest

from exceptions import ValidationError
from input_validation import (
    ALLOWED_PROJECT_FOLDERS,
    ALLOWED_PROJECT_TYPES,
    validate_csv_file_path,
    validate_optional_project_folder,
    validate_optional_project_type,
    validate_optional_workspace_directory,
    validate_workspace_path_required,
)

def _rand_text(rng: random.Random, max_len: int = 128) -> str:
    if rng.random() < 0.08:
        return ""
    n = rng.randint(0, max_len)
    # Exclude NUL: Path.resolve() raises ValueError for embedded null (not ValidationError).
    alphabet = string.ascii_letters + string.digits + string.punctuation + " \t\n\rあ🔒"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _pick_optional_project_type_arg(rng: random.Random) -> Any:
    choice = rng.randint(0, 8)
    if choice == 0:
        return None
    if choice == 1:
        return ""
    if choice == 2:
        return rng.choice(tuple(ALLOWED_PROJECT_TYPES))
    if choice == 3:
        return _rand_text(rng, 64)
    if choice == 4:
        return rng.randint(-2**31, 2**31 - 1)
    if choice == 5:
        return rng.randint(0, 2**256)
    if choice == 6:
        return b"bytes-not-str"
    if choice == 7:
        return []
    return {"CVE": "invalid-container"}


def _pick_optional_project_folder_arg(rng: random.Random) -> Any:
    choice = rng.randint(0, 9)
    if choice == 0:
        return None
    if choice == 1:
        return ""
    if choice == 2:
        return rng.choice(tuple(ALLOWED_PROJECT_FOLDERS))
    if choice == 3:
        return _rand_text(rng, 80)
    if choice == 4:
        return rng.randint(0, sys.maxsize)
    if choice == 5:
        return b"Intelx_Crawler"
    if choice == 6:
        return []
    return _rand_text(rng, 12)


def _pick_workspace_optional_arg(rng: random.Random, existing_dir: Path) -> Any:
    choice = rng.randint(0, 10)
    if choice == 0:
        return None
    if choice == 1:
        return ""
    if choice == 2:
        return str(existing_dir)
    if choice == 3:
        return str(existing_dir / ("does-not-exist-" + _rand_text(rng, 8)))
    if choice == 4:
        return _rand_text(rng, 120)
    if choice == 5:
        return "/nonexistent-root-" + str(rng.randint(0, 999_999_999))
    if choice == 6:
        return rng.randint(0, 9)
    if choice == 7:
        return b"/tmp/not-a-str"
    if choice == 8:
        return "  padded  "
    return ["workspace"]


def _pick_workspace_required_arg(rng: random.Random, existing_dir: Path) -> Any:
    choice = rng.randint(0, 10)
    if choice == 0:
        return None
    if choice == 1:
        return ""
    if choice == 2:
        return str(existing_dir)
    if choice == 3:
        return _rand_text(rng, 100)
    if choice == 4:
        return str(existing_dir / _rand_text(rng, 12))
    if choice == 5:
        return rng.choice([[], (), {}, 42, 3.14])
    if choice == 6:
        return b"/bytes-path"
    if choice == 7:
        return "  strip-me  "
    return "/missing-" + str(rng.randint(0, 10**9))


def _pick_csv_arg(rng: random.Random, existing_file: Path, garbage_parent: Path) -> Any:
    choice = rng.randint(0, 10)
    if choice == 0:
        return ""
    if choice == 1:
        return str(existing_file)
    if choice == 2:
        return existing_file
    if choice == 3:
        return str(garbage_parent / (_rand_text(rng, 24) + ".csv"))
    if choice == 4:
        return _rand_text(rng, 200)
    if choice == 5:
        return rng.randint(0, 10**6)
    if choice == 6:
        return b"/tmp/x.csv"
    if choice == 7:
        return Path("/nonexistent-file-" + str(rng.randint(0, 99999)))
    if choice == 8:
        return "  relative.csv  "
    return existing_file if rng.random() < 0.5 else str(existing_file)


def _assert_return_optional_type(out: Any) -> None:
    assert out is None or out in ALLOWED_PROJECT_TYPES, out


def _assert_return_optional_folder(out: Any) -> None:
    assert out is None or out in ALLOWED_PROJECT_FOLDERS, out


def _assert_optional_workspace(out: Any) -> None:
    assert out is None or isinstance(out, Path), out


def _assert_required_workspace(out: Any) -> None:
    assert isinstance(out, Path), out


def _assert_csv_path(out: Any) -> None:
    assert isinstance(out, Path), out


def run_fuzz_input_validation_iterations(
    iterations: int,
    *,
    tmp_dir: Path,
    rng: random.Random | None = None,
) -> None:
    rng = rng or random.Random()
    good_csv = tmp_dir / "fuzz_ok.csv"
    good_csv.write_text("col\nval\n", encoding="utf-8")
    missing_csv_parent = tmp_dir / "missing-place"
    missing_csv_parent.mkdir(exist_ok=True)

    dispatch: list[tuple[str, Callable[[], Any], Callable[[Any], None]]] = [
        ("validate_optional_project_type", lambda: validate_optional_project_type(_pick_optional_project_type_arg(rng)), _assert_return_optional_type),
        ("validate_optional_project_folder", lambda: validate_optional_project_folder(_pick_optional_project_folder_arg(rng)), _assert_return_optional_folder),
        ("validate_optional_workspace_directory", lambda: validate_optional_workspace_directory(_pick_workspace_optional_arg(rng, tmp_dir)), _assert_optional_workspace),
        ("validate_workspace_path_required", lambda: validate_workspace_path_required(_pick_workspace_required_arg(rng, tmp_dir)), _assert_required_workspace),
        ("validate_csv_file_path", lambda: validate_csv_file_path(_pick_csv_arg(rng, good_csv, missing_csv_parent)), _assert_csv_path),
    ]

    for i in range(iterations):
        name, call, check_ok = dispatch[rng.randint(0, len(dispatch) - 1)]
        try:
            out = call()
        except ValidationError:
            continue
        except Exception as e:
            raise AssertionError(
                f"[{i}] {name}: unexpected {type(e).__name__}: {e!r}"
            ) from e
        else:
            check_ok(out)


def test_fuzz_input_validation_module_1000_random_inputs(tmp_path: Path) -> None:
    """
    **Specific module:** ``input_validation`` (strict CTI path/type validators).

    1,000 randomized calls: success returns must be well-typed; failures must be
    :class:`~exceptions.ValidationError` only — never an unhandled generic exception.
    """
    run_fuzz_input_validation_iterations(1000, tmp_dir=tmp_path, rng=random.Random(42))


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        run_fuzz_input_validation_iterations(1000, tmp_dir=td_path, rng=random.Random(12345))
    print("fuzz_input_validation: 1000 iterations OK", file=sys.stderr)
