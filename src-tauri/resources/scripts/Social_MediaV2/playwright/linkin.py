import csv
import os
from playwright.sync_api import sync_playwright

# 創建 output 資料夾
output_folder = "out_linkin"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# 讀取 CSV 文件
csv_file = "threeireland/threeireland_linkedin.csv"

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
    
    # 創建上下文，模擬真實用戶
    context = browser.new_context(
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        viewport={'width': 1920, 'height': 1080},
        extra_http_headers={
            'Accept-Language': 'en-US,en;q=0.9',
        }
    )
    
    page = context.new_page()
    
    # 隱藏 webdriver 特徵
    page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });
    """)

    # 讀取 CSV 並處理每一行
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):  # 從第2行開始（第1行是標題）
            url = row.get('url', '').strip()
            
            if not url:
                print(f"第 {row_num} 行沒有 URL，跳過")
                continue
            
            print(f"處理第 {row_num} 行: {url}")
            
            try:
                # 訪問網頁
                page.goto(url, timeout=60000)

                # 等網頁載入
                page.wait_for_timeout(3000)

                # LinkedIn 特定的 modal 處理
                try:
                    # 方法1: 關閉登入提示 modal
                    login_modal_selectors = [
                        'button[aria-label="Dismiss"]',
                        'button[data-tracking-control-name="public_post_embed-header-signin-dismiss"]',
                        '.modal__dismiss',
                        '[data-test-modal-close-btn]'
                    ]
                    
                    modal_closed = False
                    for selector in login_modal_selectors:
                        try:
                            if page.locator(selector).count() > 0:
                                page.click(selector, timeout=5000)
                                print(f"成功關閉 LinkedIn modal: {selector}")
                                modal_closed = True
                                page.wait_for_timeout(1000)
                                break
                        except:
                            continue
                    
                    if not modal_closed:
                        # 方法2: 嘗試按 ESC 鍵
                        page.keyboard.press("Escape")
                        print("嘗試按 ESC 鍵關閉 modal")
                        page.wait_for_timeout(1000)
                        
                except Exception as e:
                    print(f"處理 LinkedIn modal 失敗: {str(e)}")

                # 移除可能干擾截圖的元素 (類似 Facebook 版本)
                js = """
                    // 移除登入提示和廣告
                    document.querySelectorAll('.modal, .overlay, [data-test-modal]').forEach(e => e.remove());
                    // 移除頂部導航欄 (如果存在)
                    document.querySelectorAll('.global-nav, .nav-header').forEach(e => e.remove());
                    // 移除底部固定元素
                    document.querySelectorAll('.bottom-banner, .cookie-banner').forEach(e => e.remove());
                """
                page.evaluate(js)

                # 讓畫面穩定
                page.wait_for_timeout(2000)
                
                # 等待頁面載入完成
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass  # 如果超時就繼續執行

                # 截圖，使用行號作為檔名
                screenshot_path = os.path.join(output_folder, f"{row_num}.png")
                page.screenshot(path=screenshot_path, full_page=False, timeout=60000)
                print(f"已儲存截圖: {screenshot_path}")
                
            except Exception as e:
                print(f"處理第 {row_num} 行時發生錯誤: {str(e)}")
                continue

    browser.close()

print("所有截圖完成！")
