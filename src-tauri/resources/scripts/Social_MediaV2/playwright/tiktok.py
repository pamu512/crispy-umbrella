import csv
import os
from urllib.parse import unquote
from playwright.sync_api import sync_playwright

# 創建 output 資料夾
output_folder = "out_tiktok"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# 讀取 CSV 文件
csv_file = "Wayne/Wayne_tiktok.csv"

with sync_playwright() as p:
    # 使用更真實的瀏覽器設置 (類似 Instagram 版本)
    browser = p.chromium.launch(
        headless=True,
        args=[
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--no-sandbox'
        ]
    )
    
    # 創建上下文，模擬真實用戶（iPhone）
    context = browser.new_context(
        user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        viewport={'width': 393, 'height': 852},
        extra_http_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        }
    )
    
    page = context.new_page()
    
    # 隱藏 webdriver 特徵（增強版）
    page.add_init_script("""
        // 隱藏 webdriver 屬性
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });
        
        // 偽造 plugins (iPhone Safari 沒有插件)
        Object.defineProperty(navigator, 'plugins', {
            get: () => [],
        });
        
        // 偽造 languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
        });
        
        // 偽造 hardwareConcurrency (iPhone 通常是 6 核心)
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => 6,
        });
        
        // iPhone Safari 沒有 deviceMemory，移除它
        if (navigator.deviceMemory) {
            delete navigator.deviceMemory;
        }
        
        // 偽造 permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        
        // iPhone Safari 沒有 chrome 對象，移除它
        if (window.chrome) {
            delete window.chrome;
        }
        
        // 偽造 permissions
        Object.defineProperty(navigator, 'permissions', {
            get: () => ({
                query: () => Promise.resolve({ state: 'granted' }),
            }),
        });
        
        // 偽造 WebGL 信息 (iPhone Apple GPU)
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) {
                return 'Apple Inc.';
            }
            if (parameter === 37446) {
                return 'Apple GPU';
            }
            return getParameter.call(this, parameter);
        };
        
        // 偽造 canvas 指紋
        const toBlob = HTMLCanvasElement.prototype.toBlob;
        const toDataURL = HTMLCanvasElement.prototype.toDataURL;
        const getImageData = CanvasRenderingContext2D.prototype.getImageData;
        
        // 移除 automation 相關屬性
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
    """)

    # 讀取 CSV 並處理每一行
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):  # 從第2行開始（第1行是標題）
            url = row.get('url', '').strip()
            
            if not url:
                print(f"第 {row_num} 行沒有 URL，跳過")
                continue
            
            # 將 %40 替換為 @ (URL 解碼)
            url = unquote(url)
            
            print(f"處理第 {row_num} 行: {url}")
            
            try:
                # 訪問網頁
                page.goto(url, timeout=60000)
                
                # 等網頁載入
                page.wait_for_timeout(3000)

                # 處理 modal
                try:
                    # 檢查是否有阻止 modal
                    blocking_texts = [
                        "blocked", "verify", "captcha", "robot",
                        "automated", "suspicious", "security check",
                        "請驗證", "驗證", "阻擋"
                    ]
                    
                    page_text = page.content().lower()
                    has_blocking_modal = any(text.lower() in page_text for text in blocking_texts)
                    if has_blocking_modal:
                        print("檢測到可能的阻止 modal")
                    
                    # 關閉 modal 按鈕選擇器
                    modal_selectors = [
                        'button[aria-label="Close"]',
                        'button[aria-label="Dismiss"]',
                        'button[aria-label*="關閉"]',
                        '[data-testid="app-bar-close"]',
                        '[data-e2e="modal-close-inner-button"]',
                        '.tiktok-modal-close',
                        'button[class*="close"]',
                        'svg[aria-label="Close"]',
                        '[data-testid="close-button"]',
                        '[data-testid="dismiss-button"]'
                    ]
                    
                    # 嘗試點擊關閉按鈕
                    for selector in modal_selectors:
                        try:
                            if page.locator(selector).count() > 0:
                                page.locator(selector).first.click(timeout=3000)
                                print(f"成功關閉 modal: {selector}")
                                page.wait_for_timeout(1000)
                                break
                        except:
                            continue
                    
                    # 使用 JavaScript 強制移除 modal
                    removed_count = page.evaluate("""
                        (() => {
                            let count = 0;
                            const selectors = [
                                '[role="dialog"]', '[role="alertdialog"]',
                                '.modal', '.overlay', '[class*="modal"]',
                                '[class*="Modal"]', '[data-testid="modal"]'
                            ];
                            selectors.forEach(sel => {
                                document.querySelectorAll(sel).forEach(el => {
                                    const text = (el.textContent || '').toLowerCase();
                                    if (text.includes('blocked') || text.includes('verify') || 
                                        text.includes('captcha') || el.style.zIndex > 1000) {
                                        el.remove();
                                        count++;
                                    }
                                });
                            });
                            return count;
                        })()
                    """)
                    if removed_count > 0:
                        print(f"移除了 {removed_count} 個 modal 元素")
                    
                    # 嘗試按 ESC 鍵
                    page.keyboard.press("Escape")
                    page.wait_for_timeout(500)
                            
                except Exception as e:
                    print(f"處理 modal 失敗: {str(e)}")

                # 移除干擾截圖的元素
                page.evaluate("""
                    document.querySelectorAll('.modal, .overlay, [data-testid="modal"], [role="dialog"]').forEach(e => e.remove());
                    document.querySelectorAll('[data-testid="AppBar"], .nav-header, header[role="banner"]').forEach(e => e.remove());
                    document.querySelectorAll('.bottom-banner, .cookie-banner, [data-testid="BottomBar"]').forEach(e => e.remove());
                    document.querySelectorAll('[data-testid="SideNav"], [data-testid="primaryColumn"] aside').forEach(e => e.remove());
                """)

                # 讓畫面穩定
                page.wait_for_timeout(2000)
                
                # 等待頁面載入完成
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass

                # 截圖（只截取可見區域）
                screenshot_path = os.path.join(output_folder, f"{row_num}.png")
                page.screenshot(path=screenshot_path, timeout=60000)
                print(f"已儲存截圖: {screenshot_path}")
                
            except Exception as e:
                print(f"處理第 {row_num} 行時發生錯誤: {str(e)}")
                continue

    browser.close()

print("所有截圖完成！")

