#!/usr/bin/env python3
"""
Ingest MROP RAG shards from docs/mrop-rag into JSONL for vector DB / embedding pipelines.

  python3 scripts/ingest_mrop_rag.py
  python3 scripts/ingest_mrop_rag.py --out /tmp/mrop_chunks.jsonl --max-chars 6000

No third-party deps: reads manifest.json + raw UTF-8 text. Optional chunking uses a
sliding window on characters (boundary-safe for UTF-8).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_mrop_dir() -> Path:
    return _repo_root() / "docs" / "mrop-rag"


def _load_manifest(mrop_dir: Path) -> dict:
    p = mrop_dir / "manifest.json"
    if not p.is_file():
        raise FileNotFoundError(f"Missing manifest: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _char_windows(text: str, max_chars: int, overlap: int) -> list[tuple[int, int, str]]:
    """Return list of (start, end, slice) covering text with optional overlap."""
    if max_chars <= 0 or len(text) <= max_chars:
        return [(0, len(text), text)]
    out: list[tuple[int, int, str]] = []
    step = max(1, max_chars - max(0, overlap))
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        out.append((start, end, text[start:end]))
        if end >= len(text):
            break
        start += step
    return out


def _chunk_records(
    *,
    chunk_id: str,
    path: Path,
    summary: str,
    tags: list[str],
    load_priority: int,
    format_name: str,
    max_chars: int,
    overlap: int,
) -> list[dict]:
    raw = path.read_text(encoding="utf-8")
    windows = _char_windows(raw, max_chars, overlap)
    records: list[dict] = []
    for i, (s, e, body) in enumerate(windows):
        part_id = f"{chunk_id}" if len(windows) == 1 else f"{chunk_id}__part{i}"
        text = (
            f"[MROP chunk: {chunk_id} | file: {path.name} | bytes {s}-{e}]\n"
            f"[Summary: {summary}]\n\n"
            f"{body}"
        )
        records.append(
            {
                "id": part_id,
                "text": text,
                "metadata": {
                    "mrop_chunk_id": chunk_id,
                    "source_path": str(path.resolve()),
                    "relative_path": path.name,
                    "format": format_name,
                    "load_priority": load_priority,
                    "tags": tags,
                    "summary": summary,
                    "char_span": [s, e],
                    "part_index": i,
                    "part_count": len(windows),
                },
            }
        )
    return records


def run(
    mrop_dir: Path,
    out_path: Path | None,
    max_chars: int,
    overlap: int,
    dry_run: bool,
) -> int:
    manifest = _load_manifest(mrop_dir)
    chunks = manifest.get("chunks") or []
    chunks_sorted = sorted(chunks, key=lambda c: (c.get("load_priority", 99), c.get("id", "")))

    all_records: list[dict] = []
    for c in chunks_sorted:
        cid = c.get("id")
        rel = c.get("path")
        if not cid or not rel:
            print(f"skip invalid manifest entry: {c!r}", file=sys.stderr)
            continue
        path = (mrop_dir / rel).resolve()
        if not path.is_file():
            print(f"skip missing file for {cid}: {path}", file=sys.stderr)
            continue
        summary = str(c.get("summary") or "")
        tags = c.get("tags") if isinstance(c.get("tags"), list) else []
        fmt = str(c.get("format") or path.suffix.lstrip("."))
        prio = int(c.get("load_priority", 99))
        all_records.extend(
            _chunk_records(
                chunk_id=cid,
                path=path,
                summary=summary,
                tags=[str(t) for t in tags],
                load_priority=prio,
                format_name=fmt,
                max_chars=max_chars,
                overlap=overlap,
            )
        )

    if dry_run:
        print(f"Would write {len(all_records)} JSONL record(s) from {len(chunks_sorted)} manifest row(s).")
        for r in all_records:
            print(r["id"])
        return 0

    if out_path is None:
        out_path = mrop_dir / "mrop_chunks.jsonl"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(all_records)} line(s) to {out_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="MROP RAG → JSONL ingest for embeddings")
    ap.add_argument(
        "--mrop-dir",
        type=Path,
        default=None,
        help=f"Directory containing manifest.json (default: {_default_mrop_dir()})",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSONL path (default: <mrop-dir>/mrop_chunks.jsonl)",
    )
    ap.add_argument(
        "--max-chars",
        type=int,
        default=0,
        help="Max characters per embedding window; 0 = whole file per record (default)",
    )
    ap.add_argument(
        "--overlap",
        type=int,
        default=400,
        help="Character overlap between windows when --max-chars > 0 (default 400)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="List chunk ids that would be written; do not write file",
    )
    args = ap.parse_args()
    mrop_dir = (args.mrop_dir or _default_mrop_dir()).resolve()
    return run(
        mrop_dir=mrop_dir,
        out_path=args.out,
        max_chars=max(0, args.max_chars),
        overlap=max(0, args.overlap),
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    raise SystemExit(main())
