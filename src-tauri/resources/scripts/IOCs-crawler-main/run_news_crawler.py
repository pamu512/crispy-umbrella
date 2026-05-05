#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IOC/news site crawlers — SQLite only (**CTI_DB_PATH**). No RethinkDB, Redis, or Celery.

Run from repo IOCs-crawler-main with workspace on PYTHONPATH; host sets **CTI_DB_PATH**.
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    os.chdir(ROOT)
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    if not (os.environ.get("CTI_DB_PATH") or "").strip() and not (
        os.environ.get("VAULT_PATH") or ""
    ).strip():
        print("ERROR: CTI_DB_PATH (or VAULT_PATH) must point at the vault SQLite file.", file=sys.stderr)
        return 1

    # (module_name relative to package news), entry_function_name
    jobs: list[tuple[str, str]] = [
        ("news.bleepingcomputer", "getBleeping_computer"),
        ("news.elastic_security_labs", "getElastic_security_labs"),
        ("news.thehackernews", "getThehackernews"),
        ("news.googlecloud_threat_intelligence", "getGooglecloud_threat_intelligence"),
        ("news.fortinet", "getFortinet"),
        ("news.socket_dev", "getSocket_dev"),
        ("news.sentinelone", "getSentinelone"),
        ("news.trendmicro", "getTrendmicro"),
        ("news.research_checkpoint", "getResearch_checkpoint"),
        ("news.securityweek", "getSecurityweek"),
        ("news.securityaffairs", "getSecurityaffairs"),
        ("news.cyberscoop", "getCyberscoop"),
        ("news.talosintelligence", "getTalosintelligence"),
    ]

    errors: list[str] = []
    ok = 0
    for mod_name, fn_name in jobs:
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name)
            fn()
            ok += 1
        except Exception as e:
            errors.append(f"{mod_name}.{fn_name}: {e}\n{traceback.format_exc()}")

    # Emit marker parsed by Rust ingest helpers when present
    print(f"CRAWL_SOURCES_OK:{ok}", flush=True)
    if errors:
        print("--- crawler source errors ---", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        # Partial success still refreshes IOC rows downstream
        print(f"INGESTED:{ok}", flush=True)
        return 0 if ok > 0 else 1

    print(f"INGESTED:{ok}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
