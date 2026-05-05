import os

from ..utils import iter_urls, read_csv_rows, sanitize_filename


def screenshot_instagram(csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    from playwright.sync_api import sync_playwright
    from tqdm import tqdm

    rows = read_csv_rows(csv_file)
    total_rows = len(rows)
    print(f"[instagram] Total rows to process: {total_rows}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        with tqdm(total=total_rows, desc="instagram", unit="url") as pbar:
            for row_num, url in iter_urls(rows):
                if not url:
                    tqdm.write(f"[instagram] Row {row_num} has no URL, skipping")
                    pbar.update(1)
                    continue

                tqdm.write(f"[instagram] Processing row {row_num}: {url}")
                try:
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(3000)

                    # Try to close popup
                    try:
                        if page.locator('svg[aria-label="Close"]').count() > 0:
                            page.click('svg[aria-label="Close"]')
                        elif page.locator('[aria-label="Close"]').count() > 0:
                            page.click('[aria-label="Close"]')
                        else:
                            page.keyboard.press("Escape")
                    except Exception:
                        pass

                    page.wait_for_timeout(2000)

                    safe_name = sanitize_filename(url)
                    screenshot_path = os.path.join(output_folder, f"{safe_name}.png")
                    page.screenshot(path=screenshot_path, full_page=True, timeout=60000)
                    tqdm.write(f"[instagram] Screenshot saved: {screenshot_path}")
                except Exception as e:
                    tqdm.write(f"[instagram] Error processing row {row_num}: {str(e)}")

                pbar.update(1)

        browser.close()

    print("[instagram] All screenshots completed!")

