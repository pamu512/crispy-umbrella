import os
from urllib.parse import unquote

from ..utils import iter_urls, read_csv_rows, sanitize_filename


def screenshot_tiktok(csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    from playwright.sync_api import sync_playwright
    from tqdm import tqdm

    rows = read_csv_rows(csv_file)
    total_rows = len(rows)
    print(f"[tiktok] Total rows to process: {total_rows}")

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
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            viewport={"width": 393, "height": 852},
            extra_http_headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Cache-Control": "max-age=0",
                "DNT": "1",
            },
        )

        page = context.new_page()

        page.add_init_script(
            """
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 6 });
            if (navigator.deviceMemory) { delete navigator.deviceMemory; }
            if (window.chrome) { delete window.chrome; }
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
            """
        )

        with tqdm(total=total_rows, desc="tiktok", unit="url") as pbar:
            for row_num, url in iter_urls(rows):
                if not url:
                    tqdm.write(f"[tiktok] Row {row_num} has no URL, skipping")
                    pbar.update(1)
                    continue

                url = unquote(url)
                tqdm.write(f"[tiktok] Processing row {row_num}: {url}")

                try:
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(3000)

                    # Try to close / remove modals
                    try:
                        modal_selectors = [
                            'button[aria-label="Close"]',
                            'button[aria-label="Dismiss"]',
                            'button[aria-label*="Close"]',
                            '[data-testid="app-bar-close"]',
                            '[data-e2e="modal-close-inner-button"]',
                            ".tiktok-modal-close",
                            'button[class*="close"]',
                            'svg[aria-label="Close"]',
                            '[data-testid="close-button"]',
                            '[data-testid="dismiss-button"]',
                        ]
                        for selector in modal_selectors:
                            try:
                                if page.locator(selector).count() > 0:
                                    page.locator(selector).first.click(timeout=3000)
                                    page.wait_for_timeout(800)
                                    break
                            except Exception:
                                continue
                        page.keyboard.press("Escape")
                        page.wait_for_timeout(300)
                    except Exception:
                        pass

                    page.evaluate(
                        """
                        document.querySelectorAll('.modal, .overlay, [data-testid="modal"], [role="dialog"]').forEach(e => e.remove());
                        document.querySelectorAll('[data-testid="AppBar"], .nav-header, header[role="banner"]').forEach(e => e.remove());
                        document.querySelectorAll('.bottom-banner, .cookie-banner, [data-testid="BottomBar"]').forEach(e => e.remove());
                        document.querySelectorAll('[data-testid="SideNav"], [data-testid="primaryColumn"] aside').forEach(e => e.remove());
                        """
                    )

                    page.wait_for_timeout(2000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                    safe_name = sanitize_filename(url)
                    screenshot_path = os.path.join(output_folder, f"{safe_name}.png")
                    page.screenshot(path=screenshot_path, timeout=60000)
                    tqdm.write(f"[tiktok] Screenshot saved: {screenshot_path}")

                except Exception as e:
                    tqdm.write(f"[tiktok] Error processing row {row_num}: {str(e)}")

                pbar.update(1)

        browser.close()

    print("[tiktok] All screenshots completed!")

