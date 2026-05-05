import os

from ..utils import iter_urls, read_csv_rows, sanitize_filename


def screenshot_generic(csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    """
    Generic screenshotter: open each URL and take a full-page screenshot.
    No platform-specific cleanup.
    """
    from playwright.sync_api import sync_playwright
    from tqdm import tqdm

    rows = read_csv_rows(csv_file)
    total_rows = len(rows)
    print(f"[generic] Total rows to process: {total_rows}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        with tqdm(total=total_rows, desc="generic", unit="url") as pbar:
            for row_num, url in iter_urls(rows):
                if not url:
                    tqdm.write(f"[generic] Row {row_num} has no URL, skipping")
                    pbar.update(1)
                    continue

                tqdm.write(f"[generic] Processing row {row_num}: {url}")
                try:
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(2000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                    safe_name = sanitize_filename(url)
                    screenshot_path = os.path.join(output_folder, f"{safe_name}.png")
                    page.screenshot(path=screenshot_path, full_page=True, timeout=60000)
                    tqdm.write(f"[generic] Screenshot saved: {screenshot_path}")
                except Exception as e:
                    tqdm.write(f"[generic] Error processing row {row_num}: {str(e)}")

                pbar.update(1)

        browser.close()

    print("[generic] All screenshots completed!")

