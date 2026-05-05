#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
playwright/main.py - Screenshot generator for CSV results

Reads CSV files produced by this project (output/<target>/<target>_<platform>.csv)
and saves screenshots to output_screenshot_<target>/...
"""

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright


def _safe_filename(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^\w\-\.]+", "_", s, flags=re.UNICODE)
    return s or "unknown"


def _discover_target_folders(input_root: Path) -> List[Path]:
    if not input_root.exists():
        raise FileNotFoundError(f"input_root not found: {input_root}")
    return sorted([p for p in input_root.iterdir() if p.is_dir()])


def _resolve_target_folder(input_root: Path, target: Optional[str]) -> Path:
    if target:
        # Try exact match first
        target_dir = input_root / target
        if target_dir.exists() and target_dir.is_dir():
            return target_dir
        # Fallback: try variants (two-word query might be stored as "X" or X+Y)
        for variant in [
            f'"{target}"',  # old: with quotes
            target.replace(" ", "+"),  # Three+Ireland
        ]:
            candidate = input_root / variant
            if candidate.exists() and candidate.is_dir():
                return candidate
        raise FileNotFoundError(f"target folder not found: {target_dir}")
    candidates = _discover_target_folders(input_root)
    if len(candidates) == 1:
        return candidates[0]

    names = ", ".join([p.name for p in candidates]) or "(none)"
    raise ValueError(
        f"--target not provided and input_root has {len(candidates)} folders: {names}. "
        f"Please specify --target."
    )


def _discover_csv_files(target_dir: Path) -> Dict[str, Path]:
    """
    Returns mapping: platform -> csv_path
    Expected filename: <target>_<platform>.csv
    """
    target = target_dir.name
    csvs: Dict[str, Path] = {}
    for p in sorted(target_dir.glob("*.csv")):
        m = re.match(rf"^{re.escape(target)}_(.+)\.csv$", p.name, flags=re.IGNORECASE)
        if not m:
            continue
        platform = m.group(1).lower()
        csvs[platform] = p
    return csvs


def _get_url(row: Dict[str, str]) -> str:
    for key in ("url", "URL", "link", "Link"):
        val = (row.get(key) or "").strip()
        if val:
            return val
    return ""


def _context_for_platform(browser: Browser, platform: str) -> BrowserContext:
    # Keep this conservative; over-customization can break pages.
    platform = platform.lower()

    if platform in {"tiktok"}:
        return browser.new_context(
            user_agent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                "Mobile/15E148 Safari/604.1"
            ),
            viewport={"width": 393, "height": 852},
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )

    # YouTube: wider viewport for video + sidebar
    if platform in {"youtube"}:
        return browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1920, "height": 1080},
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )

    # Default desktop-ish context (Facebook, Instagram, Twitter, LinkedIn, Pinterest, Reddit, Snapchat)
    return browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1920, "height": 1080},
        extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
    )


def _apply_stealth(page: Page) -> None:
    # Lightweight webdriver masking.
    page.add_init_script(
        """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        """
    )


def _dismiss_common_overlays(page: Page) -> None:
    # Best-effort: try click common close/dismiss buttons, then remove dialogs.
    selectors = [
        'button[aria-label="Close"]',
        'button[aria-label="Dismiss"]',
        'svg[aria-label="Close"]',
        '[aria-label="Close"]',
        '[data-testid="close-button"]',
        '[data-testid="dismiss-button"]',
        'button:has-text("Close")',
        'button:has-text("Dismiss")',
        'button:has-text("Accept")',
        'button:has-text("I Agree")',
    ]
    for sel in selectors:
        try:
            loc = page.locator(sel)
            if loc.count() > 0:
                loc.first.click(timeout=1500)
                page.wait_for_timeout(300)
                break
        except Exception:
            continue

    try:
        page.keyboard.press("Escape")
    except Exception:
        pass

    try:
        page.evaluate(
            """
            (() => {
              const selectors = [
                '[role="dialog"]', '[role="alertdialog"]',
                '.modal', '.overlay',
                '[class*="modal"]', '[class*="Modal"]',
                '[data-testid*="modal"]'
              ];
              selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => el.remove());
              });
            })();
            """
        )
    except Exception:
        pass


def _screenshot_csv(
    *,
    csv_path: Path,
    platform: str,
    output_dir: Path,
    browser: Browser,
    max_rows: Optional[int],
    timeout_ms: int,
    wait_ms: int,
    full_page: bool,
) -> Tuple[int, int]:
    """
    Returns: (processed, saved)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    processed = 0
    saved = 0

    context = _context_for_platform(browser, platform)
    page = context.new_page()
    _apply_stealth(page)

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            if max_rows is not None and processed >= max_rows:
                break

            url = _get_url(row)
            if not url:
                continue

            processed += 1
            try:
                page.goto(url, timeout=timeout_ms)
                page.wait_for_timeout(wait_ms)
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                _dismiss_common_overlays(page)
                page.wait_for_timeout(300)

                screenshot_path = output_dir / f"{row_num}.png"
                page.screenshot(path=str(screenshot_path), full_page=full_page, timeout=timeout_ms)
                saved += 1
                print(f"[{platform}] saved: {screenshot_path}")
            except Exception as e:
                print(f"[{platform}] row {row_num} failed: {url} ({e})")
                continue

    try:
        context.close()
    except Exception:
        pass

    return processed, saved


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate screenshots from output CSVs")
    parser.add_argument("--input-root", default="output", help="Directory containing target folders (default: output)")
    parser.add_argument("--target", default=None, help="Target folder name under input-root (e.g. Wayne)")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for screenshots (default: sibling of input-root named output_screenshot_<target>)",
    )
    parser.add_argument(
        "--platforms",
        default=None,
        help="Comma-separated platforms to run (default: detect from CSV filenames)",
    )
    parser.add_argument(
        "--skip-platforms",
        default=None,
        help="Comma-separated platforms to skip (default: none). Example: tiktok",
    )
    parser.add_argument("--max-rows", type=int, default=None, help="Max rows per CSV to screenshot (default: all)")
    parser.add_argument("--timeout-ms", type=int, default=60000, help="Navigation/screenshot timeout in ms")
    parser.add_argument("--wait-ms", type=int, default=2000, help="Extra wait after navigation in ms")
    parser.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode (default: True)")
    parser.add_argument("--headed", action="store_true", help="Run browser with visible window (overrides --headless)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    input_root = Path(args.input_root).resolve()
    target_dir = _resolve_target_folder(input_root, args.target)
    target = target_dir.name

    default_output = input_root.parent / f"output_screenshot_{_safe_filename(target)}"
    output_root = Path(args.output_dir).resolve() if args.output_dir else default_output

    csvs = _discover_csv_files(target_dir)
    if not csvs:
        raise FileNotFoundError(f"No CSV files found in {target_dir} (expected: {target}_<platform>.csv)")

    if args.platforms:
        allow = {p.strip().lower() for p in args.platforms.split(",") if p.strip()}
        csvs = {k: v for k, v in csvs.items() if k in allow}
        if not csvs:
            raise FileNotFoundError(f"No matching CSVs for --platforms={args.platforms} in {target_dir}")

    if args.skip_platforms:
        skip = {p.strip().lower() for p in args.skip_platforms.split(",") if p.strip()}
        csvs = {k: v for k, v in csvs.items() if k not in skip}
        if not csvs:
            raise FileNotFoundError(f"All platforms were skipped by --skip-platforms={args.skip_platforms}")

    print(f"[INFO] input_root: {input_root}")
    print(f"[INFO] target: {target}")
    print(f"[INFO] screenshots: {output_root}")
    print(f"[INFO] platforms: {', '.join(sorted(csvs.keys()))}")

    totals_processed = 0
    totals_saved = 0

    headless = args.headless and not args.headed
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-dev-shm-usage", "--no-sandbox"])

        for platform, csv_path in sorted(csvs.items()):
            # Default screenshot mode:
            # - Facebook/Instagram/YouTube/Reddit/LinkedIn/TikTok: full page (long content, posts, threads, video pages)
            # - Others: visible area is faster and less likely to fail
            full_page = platform in {"facebook", "instagram", "youtube", "reddit", "linkedin", "tiktok"}
            out_dir = output_root / platform
            processed, saved = _screenshot_csv(
                csv_path=csv_path,
                platform=platform,
                output_dir=out_dir,
                browser=browser,
                max_rows=args.max_rows,
                timeout_ms=args.timeout_ms,
                wait_ms=args.wait_ms,
                full_page=full_page,
            )
            totals_processed += processed
            totals_saved += saved

        try:
            browser.close()
        except Exception:
            pass

    print(f"[DONE] processed={totals_processed} saved={totals_saved} output={output_root}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        raise


