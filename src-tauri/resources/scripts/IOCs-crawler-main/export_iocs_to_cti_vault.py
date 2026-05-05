#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Legacy compatibility shim.

IOC/news rows are written directly into **ioc_news** by ``run_news_crawler.py`` using **CTI_DB_PATH**.
RethinkDB export has been removed — this script delegates to the native crawler.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    runner = root / "run_news_crawler.py"
    env = os.environ.copy()
    proc = subprocess.run(
        [sys.executable, str(runner)],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
