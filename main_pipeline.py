#!/usr/bin/env python3
"""
CTI Command Center — portable pipeline CLI.

- **Development**: run from repo root; loads ``shared_utils`` from ``src-tauri/resources/scripts/shared_utils``.
- **Frozen (PyInstaller)**: ``shared_utils`` and ``social_media`` are unpacked under ``sys._MEIPASS``.

Examples::

    python main_pipeline.py info
    python main_pipeline.py sync --workspace "C:\\path\\to\\workspace"
    python main_pipeline.py ingest-file .\\out.csv --type IOC --project IOCs-crawler-main

Environment (vault / workspace)::

    CTI_DB_PATH, CTI_WORKSPACE_PATH, CTI_LOGS_DIR — see ``shared_utils`` README in-repo.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _meipass() -> Path | None:
    if _is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return None


def _repo_root() -> Path:
    """Directory containing this script (dev) or bundle root (frozen)."""
    mp = _meipass()
    if mp is not None:
        return mp
    return Path(__file__).resolve().parent


def _shared_utils_dir() -> Path:
    root = _repo_root()
    if _is_frozen():
        d = root / "shared_utils"
        if d.is_dir():
            return d
    d = root / "src-tauri" / "resources" / "scripts" / "shared_utils"
    return d


def _social_media_dir() -> Path:
    return _repo_root() / "social_media"


def _ensure_shared_utils_path() -> Path:
    su = _shared_utils_dir()
    if not su.is_dir():
        raise FileNotFoundError(
            f"shared_utils not found at {su}. "
            "In dev, run from repo root; in EXE, rebuild with --add-data for shared_utils."
        )
    s = str(su.resolve())
    if s not in sys.path:
        sys.path.insert(0, s)
    return su


def cmd_info(_: argparse.Namespace) -> int:
    root = _repo_root()
    su = _shared_utils_dir()
    sm = _social_media_dir()
    print("CTI Pipeline")
    print(f"  frozen:     {_is_frozen()}")
    print(f"  root:       {root}")
    print(f"  shared_utils (expected): {su}  exists={su.is_dir()}")
    print(f"  social_media:            {sm}  exists={sm.is_dir()}")
    if sm.is_dir():
        print(f"  social_media files:      {len(list(sm.iterdir()))} item(s)")
    try:
        _ensure_shared_utils_path()
        import db_manager  # noqa: WPS433

        print(f"  db_manager:  {db_manager.__file__}")
    except Exception as e:  # noqa: BLE001
        print(f"  db_manager:  (not loadable) {e}")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    ws = (args.workspace or os.environ.get("CTI_WORKSPACE_PATH") or "").strip()
    if not ws:
        print("ERROR: pass --workspace or set CTI_WORKSPACE_PATH", file=sys.stderr)
        return 2
    _ensure_shared_utils_path()
    from ingestor import run_sync  # noqa: WPS433

    out = run_sync(ws)
    print(json.dumps(out, indent=2))
    errors = [f for f in out.get("files", []) if f.get("status") == "error"]
    return 1 if errors else 0


def cmd_ingest_file(args: argparse.Namespace) -> int:
    _ensure_shared_utils_path()
    from ingestor import run_ingest_file  # noqa: WPS433

    out = run_ingest_file(args.file, args.type_, args.project)
    print(json.dumps(out, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="CTI Pipeline (vault CSV sync)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="Show bundle paths and import check")
    p_info.set_defaults(func=cmd_info)

    p_sync = sub.add_parser("sync", help="Ingest all known project CSVs under a workspace root")
    p_sync.add_argument(
        "--workspace",
        "-w",
        default=os.environ.get("CTI_WORKSPACE_PATH", ""),
        help="Workspace root (default: CTI_WORKSPACE_PATH)",
    )
    p_sync.set_defaults(func=cmd_sync)

    p_one = sub.add_parser("ingest-file", help="Ingest a single CSV into the vault")
    p_one.add_argument("file")
    p_one.add_argument("--type", dest="type_", choices=("CVE", "IOC", "ASM"), default=None)
    p_one.add_argument(
        "--project",
        choices=(
            "Intelx_Crawler",
            "CVE_Project_NVD",
            "ASM-fetch-main",
            "Ransomware_live_event_victim",
            "Phishing_and_Social_Media_All-in-one",
            "Social_MediaV2",
            "IOCs-crawler-main",
            "Compromised_user_Mac",
        ),
        default=None,
    )
    p_one.set_defaults(func=cmd_ingest_file)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
