import os

from ..utils import iter_urls, read_csv_rows, sanitize_filename


def screenshot_twitter(csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    from playwright.sync_api import sync_playwright
    from tqdm import tqdm

    rows = read_csv_rows(csv_file)
    total_rows = len(rows)
    print(f"[twitter] Total rows to process: {total_rows}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        with tqdm(total=total_rows, desc="twitter", unit="url") as pbar:
            for row_num, url in iter_urls(rows):
                if not url:
                    tqdm.write(f"[twitter] Row {row_num} has no URL, skipping")
                    pbar.update(1)
                    continue

                tqdm.write(f"[twitter] Processing row {row_num}: {url}")
                try:
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(2000)

                    page.evaluate(
                        """
                        document.querySelectorAll('[data-testid="loginButton"]').forEach(e => e.remove());
                        document.querySelectorAll('[data-testid="signupButton"]').forEach(e => e.remove());
                        document.querySelectorAll('[data-testid="sidebarColumn"]').forEach(e => e.remove());
                        document.querySelectorAll('[data-testid="BottomBar"]').forEach(e => e.remove());
                        """
                    )

                    page.wait_for_timeout(1000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                    safe_name = sanitize_filename(url)
                    screenshot_path = os.path.join(output_folder, f"{safe_name}.png")
                    page.screenshot(path=screenshot_path, timeout=60000)
                    tqdm.write(f"[twitter] Screenshot saved: {screenshot_path}")
                except Exception as e:
                    tqdm.write(f"[twitter] Error processing row {row_num}: {str(e)}")

                pbar.update(1)

        browser.close()

    print("[twitter] All screenshots completed!")

