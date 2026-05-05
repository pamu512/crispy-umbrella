import os

from ..utils import iter_urls, read_csv_rows, sanitize_filename


def screenshot_linkedin(csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    from playwright.sync_api import sync_playwright
    from tqdm import tqdm

    rows = read_csv_rows(csv_file)
    total_rows = len(rows)
    print(f"[linkedin] Total rows to process: {total_rows}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )

        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        page = context.new_page()

        page.add_init_script(
            """
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            """
        )

        with tqdm(total=total_rows, desc="linkedin", unit="url") as pbar:
            for row_num, url in iter_urls(rows):
                if not url:
                    tqdm.write(f"[linkedin] Row {row_num} has no URL, skipping")
                    pbar.update(1)
                    continue

                tqdm.write(f"[linkedin] Processing row {row_num}: {url}")
                try:
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(3000)

                    # Close login / hint modal if present
                    try:
                        login_modal_selectors = [
                            'button[aria-label="Dismiss"]',
                            'button[data-tracking-control-name="public_post_embed-header-signin-dismiss"]',
                            ".modal__dismiss",
                            "[data-test-modal-close-btn]",
                        ]
                        for selector in login_modal_selectors:
                            try:
                                if page.locator(selector).count() > 0:
                                    page.click(selector, timeout=5000)
                                    page.wait_for_timeout(1000)
                                    break
                            except Exception:
                                continue
                        page.keyboard.press("Escape")
                        page.wait_for_timeout(500)
                    except Exception:
                        pass

                    page.evaluate(
                        """
                        document.querySelectorAll('.modal, .overlay, [data-test-modal]').forEach(e => e.remove());
                        document.querySelectorAll('.global-nav, .nav-header').forEach(e => e.remove());
                        document.querySelectorAll('.bottom-banner, .cookie-banner').forEach(e => e.remove());
                        """
                    )

                    page.wait_for_timeout(2000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                    safe_name = sanitize_filename(url)
                    screenshot_path = os.path.join(output_folder, f"{safe_name}.png")
                    page.screenshot(path=screenshot_path, full_page=False, timeout=60000)
                    tqdm.write(f"[linkedin] Screenshot saved: {screenshot_path}")
                except Exception as e:
                    tqdm.write(f"[linkedin] Error processing row {row_num}: {str(e)}")

                pbar.update(1)

        browser.close()

    print("[linkedin] All screenshots completed!")

