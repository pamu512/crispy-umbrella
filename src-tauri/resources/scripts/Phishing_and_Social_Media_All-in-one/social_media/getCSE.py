# pip install playwright
# playwright install chromium

import re
import sys
import os
from urllib.parse import urlparse, parse_qsl, unquote
from playwright.sync_api import sync_playwright
import socket

# Fix encoding issues on Windows
if sys.platform.startswith('win'):
    import codecs
    try:
        # Try to set UTF-8 encoding for stdout/stderr
        if hasattr(sys.stdout, 'detach'):
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        if hasattr(sys.stderr, 'detach'):
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    except (AttributeError, OSError):
        # Fallback: just set the environment variable
        pass
    os.environ['PYTHONIOENCODING'] = 'utf-8'

ALLOWED_BASE_KEYS = {
    "rsz", "num", "hl", "source", "cselibv", "cx",
    "safe", "cse_tok", "sort", "exp", "rurl", "as_qdr"
}

def parse_base_params_from_url(full_url: str):
    qs = urlparse(full_url).query
    pairs = dict(parse_qsl(qs, keep_blank_values=True))
    # Decode necessary fields
    for k in ("rurl", "cse_tok", "exp"):
        if k in pairs:
            pairs[k] = unquote(pairs[k])
    base_params = {k: v for k, v in pairs.items() if k in ALLOWED_BASE_KEYS}
    return base_params, pairs

def capture_cse_requests(page_url: str, timeout_ms: int = 20000, headless: bool = True, use_tor: bool = False):
    """
    Open page, execute JS, intercept all upcoming cse/element/v1 requests.
    Args:
        page_url: URL to visit
        timeout_ms: Timeout in milliseconds
        headless: Run browser in headless mode
        use_tor: Use Tor proxy (SOCKS5 on 127.0.0.1:9150)
    Returns:
      - hit_urls: List of complete URLs captured in order
      - parsed:   Parsing results (base_params, all_pairs) for each URL
    """
    hit_urls = []
    parsed = []

    with sync_playwright() as p:
        browser_args = []
        if use_tor:
            # Configure Tor SOCKS5 proxy
            browser_args.extend([
                '--proxy-server=socks5://127.0.0.1:9150'
            ])
            print("Using Tor proxy (127.0.0.1:9150)")
        
        browser = p.chromium.launch(headless=headless, args=browser_args)
        context = browser.new_context()
        page = context.new_page()

        def on_request(req):
            url = req.url
            if "https://cse.google.com/cse/element/v1" in url:
                hit_urls.append(url)
                base_params, all_pairs = parse_base_params_from_url(url)
                parsed.append((base_params, all_pairs))

        page.on("request", on_request)

        # Navigate to page; wait for DOM ready first, then wait for network idle (many scripts run after loading)
        page.goto(page_url, wait_until="domcontentloaded", timeout=timeout_ms)
        # This step is crucial if site behavior is slow
        try:
            page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except:
            pass

        # If page needs interaction to trigger, add some actions here (as needed):
        # page.click("text=Search")  # Example only

        # Wait a bit more to give events a chance to trigger
        page.wait_for_timeout(1500)
        browser.close()

    return hit_urls, parsed

def get_cse_parameters(platform=None, use_tor=False):
    """
    Get latest CSE parameters
    Args:
        platform (str): Specify platform ('facebook', 'twitter', 'instagram', 'linkedin')
                       If None, get general parameters
        use_tor (bool): Use Tor proxy for anonymity
    Returns: dict - Contains latest base_params
    """
    # Platform-specific URL mapping with date sorting
    platform_urls = {
        "facebook": "https://www.social-searcher.com/facebookcse.html?q=test&sort=date",
        "twitter": "https://www.social-searcher.com/twittercse.html?q=test&sort=date", 
        "instagram": "https://www.social-searcher.com/instagramcse.html?q=test&sort=date",
        "linkedin": "https://www.social-searcher.com/linkedincse.html?q=test&sort=date",
        "tiktok": "https://www.social-searcher.com/tiktokcse.html?q=test&sort=date",
        "pinterest": "https://www.social-searcher.com/pinterestcse.html?q=test&sort=date"
    }
    
    if platform and platform in platform_urls:
        page_url = platform_urls[platform]
        print(f"Getting CSE parameters for {platform.upper()} with date sorting...")
    else:
        page_url = "https://www.social-searcher.com/google-social-search/?q=test&sort=date"
        print("Getting general CSE parameters with date sorting...")
    
    if use_tor:
        print("[SECURE] Using Tor proxy for enhanced privacy")
    
    urls, parsed = capture_cse_requests(page_url, use_tor=use_tor)

    if not urls:
        print(f"Error: Unable to get cse/element/v1 requests from {platform or 'general'}")
        return None
    else:
        print(f"Successfully captured cse/element/v1 requests for {platform or 'general'}:")
        for u in urls:
            print(" -", u)

        # Take the first one as your latest base_params
        base_params, all_pairs = parsed[0]
        print(f"\n{platform or 'General'} latest base_params:")
        for k, v in base_params.items():
            print(f"  {k} = {v}")

        return base_params

def get_all_platform_parameters(use_tor=False):
    """
    Get CSE parameters for all platforms
    Args:
        use_tor (bool): Use Tor proxy for all requests
    Returns: dict - Contains parameters for all platforms
    """
    platforms = ["facebook", "twitter", "instagram", "linkedin", "tiktok", "pinterest"]
    all_params = {}
    
    if use_tor:
        print("[SECURE] All requests will use Tor proxy for enhanced privacy")
    
    for platform in platforms:
        print(f"\n{'='*50}")
        print(f"Getting {platform.upper()} parameters...")
        params = get_cse_parameters(platform, use_tor=use_tor)
        if params:
            all_params[platform] = params
        else:
            print(f"[ERROR] Failed to get {platform} parameters")
    
    return all_params

def check_tor_connection():
    """
    Check if Tor proxy is running on 127.0.0.1:9150
    Returns: bool - True if Tor is accessible
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('127.0.0.1', 9150))
        sock.close()
        return result == 0
    except:
        return False

if __name__ == "__main__":
    
    # Check for Tor option
    use_tor = "--tor" in sys.argv or "-t" in sys.argv
    
    if use_tor:
        print("[SECURE] Tor mode enabled - checking Tor connection...")
        if check_tor_connection():
            print("[OK] Tor proxy is running on 127.0.0.1:9150")
        else:
            print("[ERROR] Tor proxy is not accessible on 127.0.0.1:9150")
            print("   Please start Tor service first!")
            sys.exit(1)
    
    # Test Tor connection
    if use_tor and not check_tor_connection():
        print("[ERROR] Tor proxy not accessible on 127.0.0.1:9150. Please ensure Tor is running.")
        sys.exit(1)
    
    # Test single platform
    # params = get_cse_parameters("facebook", use_tor=use_tor)
    # if params:
    #     print("\nSuccessfully retrieved Facebook parameters:", params)
    
    # Get all platform parameters
    all_params = get_all_platform_parameters(use_tor=use_tor)
    if all_params:
        print(f"\n{'='*50}")
        print("All platform parameters retrieval completed!")
        print(f"Successfully retrieved parameters for {len(all_params)} platforms")
        
        # Save to JSON file
        import json
        filename = "platform_cse_parameters_tor.json" if use_tor else "platform_cse_parameters.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(all_params, f, indent=2, ensure_ascii=False)
        print(f"Parameters saved to {filename}")
