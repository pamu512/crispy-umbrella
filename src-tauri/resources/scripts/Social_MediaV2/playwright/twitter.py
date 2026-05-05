import csv
import os
from playwright.sync_api import sync_playwright

# 創建 output 資料夾
output_folder = "out_twitter"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# 讀取 CSV 文件
csv_file = "Wayne/Wayne_twitter.csv"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

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
                page.wait_for_timeout(2000)

                # 選擇你要刪掉的元素（Twitter 特定的元素）
                # 可以根據需要調整這些選擇器
                js = """
                    // 刪除登入提示框
                    document.querySelectorAll('[data-testid="loginButton"]').forEach(e => e.remove());
                    document.querySelectorAll('[data-testid="signupButton"]').forEach(e => e.remove());
                    // 刪除側邊欄推薦內容
                    document.querySelectorAll('[data-testid="sidebarColumn"]').forEach(e => e.remove());
                    // 刪除底部導航欄（移動版）
                    document.querySelectorAll('[data-testid="BottomBar"]').forEach(e => e.remove());
                """
                page.evaluate(js)

                # 讓畫面穩定
                page.wait_for_timeout(1000)
                
                # 等待頁面載入完成
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass  # 如果超時就繼續執行

                # 截圖，使用行號作為檔名
                screenshot_path = os.path.join(output_folder, f"{row_num}.png")
                page.screenshot(path=screenshot_path, timeout=60000)
                print(f"已儲存截圖: {screenshot_path}")
                
            except Exception as e:
                print(f"處理第 {row_num} 行時發生錯誤: {str(e)}")
                continue

    browser.close()

print("所有截圖完成！")

