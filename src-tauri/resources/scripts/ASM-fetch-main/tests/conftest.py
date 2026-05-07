"""Pytest path setup for ASM-fetch-main (``src.*``, ``shared_utils``, repo ``exceptions``)."""

from __future__ import annotations

import sys
import types
from pathlib import Path

_ASM_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ASM_ROOT.parent
_SHARED_UTILS = _SCRIPTS / "shared_utils"
_REPO_ROOT = Path(__file__).resolve().parents[5]

for _p in (_ASM_ROOT, _SHARED_UTILS, _REPO_ROOT):
    s = str(_p)
    if s not in sys.path:
        sys.path.insert(0, s)

# Optional dependency: allow importing ``src.utils.validators`` without ``pip install validators``.
if "validators" not in sys.modules:
    _validators_stub = types.ModuleType("validators")

    def _domain(name: str) -> bool:
        return bool(name) and "." in name

    _validators_stub.domain = _domain  # type: ignore[attr-defined]
    sys.modules["validators"] = _validators_stub
