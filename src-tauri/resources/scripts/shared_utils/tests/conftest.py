"""Path setup so ``input_validation`` and repo-root ``exceptions`` import in tests."""

from __future__ import annotations

import sys
from pathlib import Path

_SHARED_UTILS = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[5]

for _p in (_SHARED_UTILS, _REPO_ROOT):
    s = str(_p)
    if s not in sys.path:
        sys.path.insert(0, s)
