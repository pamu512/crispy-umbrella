import csv
import os
from playwright.sync_api import sync_playwright

# 創建 output 資料夾
output_folder = "output_ins"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# 讀取 CSV 文件
csv_file = "threeireland/threeireland_instagram.csv"

with sync_playwright() as p:
    # 啟動瀏覽器
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    )
    page = context.new_page()

    # 讀取 CSV 並處理每一行
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            url = row.get('url', '').strip()
            
            if not url:
                print(f"第 {row_num} 行沒有 URL，跳過")
                continue
            
            print(f"處理第 {row_num} 行: {url}")
            
            try:
                # 訪問網頁
                page.goto(url, timeout=60000)
                page.wait_for_timeout(3000)
                
                # 嘗試關閉彈窗
                try:
                    # 嘗試點擊關閉按鈕
                    if page.locator('svg[aria-label="Close"]').count() > 0:
                        page.click('svg[aria-label="Close"]')
                        print("關閉了彈窗")
                    elif page.locator('[aria-label="Close"]').count() > 0:
                        page.click('[aria-label="Close"]')
                        print("關閉了彈窗")
                    else:
                        # 按 ESC 鍵
                        page.keyboard.press("Escape")
                        print("按 ESC 關閉彈窗")
                except:
                    pass
                
                # 等待一下
                page.wait_for_timeout(2000)
                
                # 截圖
                screenshot_path = os.path.join(output_folder, f"{row_num}.png")
                page.screenshot(path=screenshot_path, full_page=True, timeout=60000)
                print(f"已儲存截圖: {screenshot_path}")
                
            except Exception as e:
                print(f"處理第 {row_num} 行時發生錯誤: {str(e)}")
                continue

    browser.close()

print("所有截圖完成！")
