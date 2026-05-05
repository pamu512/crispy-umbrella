import requests
import re
import json
import csv
import os
import sys
import time
import importlib.util
import subprocess
import socket
from pathlib import Path
from requests_tor import RequestsTor
from datetime import datetime, timedelta

# Dynamic import of getCSE.py
try:
    spec = importlib.util.spec_from_file_location("getCSE", "getCSE.py")
    getCSE_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(getCSE_module)
except ImportError as e:
    print(f"Warning: Could not import getCSE module: {e}")
    getCSE_module = None

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

# ============================================================================
# Docker Tor Configuration - Two Solutions
# ============================================================================
# Solution 1: Auto-restart Docker Tor container on connection failures
# Solution 2: Use Tor control port for identity switching
# ============================================================================

# Tor configuration - can be overridden by environment variables
TOR_DOCKER_CONTAINER = os.getenv("TOR_DOCKER_CONTAINER", "docker-tor")
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")  # Use "tor_docker" in docker-compose
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))

def restart_docker_tor():
    """Restart Docker Tor container when connection fails"""
    try:
        print(f"[DOCKER] Restarting Tor container '{TOR_DOCKER_CONTAINER}'...")
        
        # First, stop the container
        stop_result = subprocess.run(
            ['docker', 'stop', TOR_DOCKER_CONTAINER],
            capture_output=True,
            text=True,
            timeout=15
        )
        if stop_result.returncode != 0:
            print(f"[DOCKER] Warning: Stop command returned {stop_result.returncode}, but continuing...")
        
        # Wait a moment for the container to fully stop
        time.sleep(2)
        
        # Then start it again
        result = subprocess.run(
            ['docker', 'start', TOR_DOCKER_CONTAINER],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"[DOCKER] Container restarted successfully")
            # Wait for Tor to be ready and verify connection
            print("[DOCKER] Waiting for Tor to initialize (this may take up to 60 seconds)...")
            max_wait = 60  # Increased wait time for Docker environment
            wait_interval = 3  # Check every 3 seconds
            waited = 0
            
            while waited < max_wait:
                time.sleep(wait_interval)
                waited += wait_interval
                
                # Try to check connection
                if check_tor_connection():
                    # Double check - verify it's really working
                    time.sleep(2)
                    if check_tor_connection():
                        print(f"[DOCKER] Tor connection verified after {waited} seconds")
                        # Additional wait to ensure Tor is fully ready
                        time.sleep(3)
                        return True
                
                if waited % 10 == 0:
                    print(f"[DOCKER] Still waiting for Tor connection... ({waited}/{max_wait}s)")
                    # Try to check container status
                    try:
                        status_result = subprocess.run(
                            ['docker', 'inspect', '--format', '{{.State.Status}}', TOR_DOCKER_CONTAINER],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if status_result.returncode == 0:
                            status = status_result.stdout.strip()
                            print(f"[DOCKER] Container status: {status}")
                    except:
                        pass
            
            print(f"[DOCKER] Warning: Tor connection not verified after {max_wait}s")
            print(f"[DOCKER] This might be a network namespace issue. Trying to continue anyway...")
            return True  # Still return True to allow retry
        else:
            print(f"[DOCKER] Failed to restart container: {result.stderr}")
            return False
    except Exception as e:
        print(f"[DOCKER] Error restarting container: {e}")
        import traceback
        print(f"[DOCKER] Traceback: {traceback.format_exc()}")
        return False

def check_tor_connection(host=None, port=None, timeout=5, verbose=False):
    """Check if Tor proxy is accessible"""
    if host is None:
        host = TOR_SOCKS_HOST
    if port is None:
        port = TOR_SOCKS_PORT
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            if verbose:
                print(f"[DEBUG] Tor connection check succeeded: host={host}, port={port}")
            return True
        else:
            if verbose:
                # Error code meanings: 111=Connection refused, 110=Connection timeout, 113=No route to host
                error_msg = {
                    111: "Connection refused (service not listening)",
                    110: "Connection timeout",
                    113: "No route to host",
                }.get(result, f"Unknown error code {result}")
                print(f"[DEBUG] Tor connection check failed: host={host}, port={port}, error={result} ({error_msg})")
            return False
    except socket.timeout:
        if verbose:
            print(f"[DEBUG] Tor connection check timeout: host={host}, port={port}")
        return False
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Tor connection check exception: {e}")
        return False

def check_tor_control_port(host=None, port=9051):
    """Check if Tor control port is accessible"""
    return check_tor_connection(host, port, timeout=2)

# Disable Solution 2 (control port), use only Solution 1 (Docker restart)
# All problems will trigger Docker restart instead of identity switching
use_control_port = None
print(f"[INFO] Using Solution 1 only: Docker restart on any issues (identity switching disabled)")

# Wait for Tor to be ready before initializing RequestsTor
def wait_for_tor(max_wait=60, check_interval=2):
    """Wait for Tor service to be ready"""
    print(f"[INIT] Waiting for Tor service to be ready...")
    waited = 0
    while waited < max_wait:
        if check_tor_connection():
            print(f"[INIT] Tor service is ready after {waited} seconds")
            return True
        time.sleep(check_interval)
        waited += check_interval
        if waited % 10 == 0:
            print(f"[INIT] Still waiting for Tor... ({waited}/{max_wait}s)")
    print(f"[INIT] Warning: Tor service not ready after {max_wait}s, but continuing...")
    return False

# Wait for Tor before initializing
wait_for_tor()

# Initialize RequestsTor with Docker Tor ports
# SOCKS port: 9050 (Docker Tor standard SOCKS proxy)
# Control port: None (disabled, using Docker restart instead)
# Docker Tor may be less stable than Tor Browser, so we use more conservative settings:
# - threads=4 (reduced from default 8) for better stability
# - autochange_id=10 (increased from default 5) to change identity less frequently
# Note: RequestsTor only supports localhost, so if TOR_SOCKS_HOST is not localhost,
# we need to use standard requests with SOCKS proxy instead
if TOR_SOCKS_HOST == "127.0.0.1" or TOR_SOCKS_HOST == "localhost":
    # Use RequestsTor for localhost connections
    rt = RequestsTor(tor_ports=(TOR_SOCKS_PORT,), tor_cport=None, threads=4, autochange_id=10)
    print(f"[INIT] RequestsTor initialized with Tor on {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
else:
    # Use standard requests with SOCKS proxy for remote host connections
    # PySocks is already in requirements.txt
    print(f"[INIT] Using SOCKS proxy for Tor on {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    # Create a custom session with SOCKS proxy
    # We'll create a wrapper class to mimic RequestsTor interface
    class SOCKSRequestsWrapper:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            # Use socks5h:// to resolve DNS through the proxy
            self.proxy_url = f'socks5h://{host}:{port}'
            self.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
        
        def get(self, url, **kwargs):
            # Handle timeout and params properly
            timeout = kwargs.pop('timeout', 60)
            return requests.get(url, proxies=self.proxies, timeout=timeout, **kwargs)
        
        def post(self, url, **kwargs):
            timeout = kwargs.pop('timeout', 60)
            return requests.post(url, proxies=self.proxies, timeout=timeout, **kwargs)
        
        def new_id(self):
            # Not supported for remote Tor, but keep interface compatible
            print("[WARNING] new_id() not supported for remote Tor proxy")
    
    rt = SOCKSRequestsWrapper(TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    print(f"[INIT] SOCKS proxy wrapper initialized for {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")

def reinitialize_tor_connection():
    """Reinitialize Tor connection after restart"""
    global rt
    if TOR_SOCKS_HOST == "127.0.0.1" or TOR_SOCKS_HOST == "localhost":
        rt = RequestsTor(tor_ports=(TOR_SOCKS_PORT,), tor_cport=None, threads=4, autochange_id=10)
    else:
        rt = SOCKSRequestsWrapper(TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    print(f"[INIT] Tor connection reinitialized for {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")

def tor_new_identity_with_auth(platform=None):
    """
    Execute TOR control port authentication and switch to new identity, refresh token, then pause for 3 seconds
    
    Args:
        platform (str): Platform name, used to get specific platform token
    
    Returns:
        dict or bool: Returns new parameters if refresh is successful, otherwise returns False
    """
    try:
        print("TOR cport auth: True. TOR NEW IDENTITY. Sleep 3 sec.")
        # Call RequestsTor's new identity method
        rt.new_id()
        # Pause for 3 seconds
        time.sleep(3)
        print("TOR identity changed successfully.")
        
        # Refresh token and other CSE parameters
        if getCSE_module:
            print(f"Refreshing CSE parameters for {platform or 'general'}...")
            try:
                new_params = getCSE_module.get_cse_parameters(platform, use_tor=True)
                if new_params:
                    print("Token refreshed successfully!")
                    return new_params
                else:
                    print("Warning: Failed to refresh token, using existing parameters")
                    return True
            except Exception as e:
                print(f"Warning: Token refresh failed: {e}")
                return True
        else:
            print("Warning: getCSE module not available, skipping token refresh")
            return True
            
    except Exception as e:
        print(f"TOR identity change failed: {e}")
        return False

# Common CSE parameters (as backup)
COMMON_PARAMS = {
    "rsz": "filtered_cse",
    "num": "10",
    "hl": "en",
    "source": "gcsc",
    "cselibv": "6467658b9628de43",
    "cx": "c0311d8946a51b053",   # Updated CSE ID
    "safe": "active",
    "cse_tok": "AEXjvhKRxdnr9hrtIZmXNycBc0R7:1759765252903",
    "sort": "date",
    "exp": "cc,apo"
}

# Platform-specific parameters
PLATFORM_URLS = {
    "facebook": "https://www.social-searcher.com/facebookcse.html",
    "instagram": "https://www.social-searcher.com/instagramcse.html",
    "linkedin": "https://www.social-searcher.com/linkedincse.html",
    "twitter": "https://www.social-searcher.com/twittercse.html",
    "tiktok": "https://www.social-searcher.com/tiktokcse.html",
    "pinterest": "https://www.social-searcher.com/pinterestcse.html"
}

def load_platform_parameters():
    """Load platform-specific parameters"""
    try:
        with open("platform_cse_parameters.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Platform parameters file not found, using general parameters")
        return None
    except Exception as e:
        print(f"Failed to load platform parameters: {e}")
        return None

def get_base_params(platform, updated_params=None):
    """Create base parameters for a specific platform"""
    # Load platform-specific parameters
    platform_params = load_platform_parameters()
    
    if platform_params and platform in platform_params:
        # Use platform-specific parameters
        params = platform_params[platform].copy()
        print(f"Using {platform.upper()} specific parameters")
    else:
        # Use general parameters as backup
        params = COMMON_PARAMS.copy()
        print(f"Using general parameters as backup for {platform.upper()}")
        params["rurl"] = PLATFORM_URLS[platform]
    
    # Override with updated parameters if available
    if updated_params:
        if isinstance(updated_params, dict):
            # Check if updated_params is a multi-platform dict (e.g., {"facebook": {...}, "twitter": {...}})
            platform_keys = ["facebook", "twitter", "instagram", "linkedin", "tiktok", "pinterest"]
            is_multi_platform_dict = any(p in updated_params for p in platform_keys)
            
            if is_multi_platform_dict:
                # This is a multi-platform dict, only use the current platform's params
                if platform in updated_params and isinstance(updated_params[platform], dict):
                    params.update(updated_params[platform])
                    print(f"Updated {platform.upper()} parameters from updated_params")
            else:
                # If updated_params contains general parameters (not platform-specific)
                # Only update if it doesn't look like a multi-platform dict
                params.update(updated_params)
    
    # Ensure date sorting is always applied
    # Fix empty string sort parameter (should be "date" not "")
    if "sort" not in params or not params["sort"] or params["sort"] == "":
        params["sort"] = "date"
        print(f"Added date sorting for {platform.upper()}")
    
    # Clean up: Remove any platform-specific keys that might have been accidentally added
    platform_keys = ["facebook", "twitter", "instagram", "linkedin", "tiktok", "pinterest"]
    for key in platform_keys:
        if key in params and key != platform:
            del params[key]
            print(f"Removed accidental {key} parameter from {platform.upper()} params")
    
    return params



def fetch_google_cse(query, base_params, num=100, platform_name=""):
    global rt  # Declare global rt at the beginning of the function
    url = "https://cse.google.com/cse/element/v1"

    all_results = []
    pages = (num // 10) + (1 if num % 10 else 0)
    cursor_printed = False  # Track if cursor info has been printed
    max_pages = pages  # Maximum pages to fetch, can be adjusted based on cursor

    i = 0
    while i < max_pages:
        page_retry_count = 0
        max_page_retries = 4  # Increased retries for Docker environment
        results = []  # Initialize results
        
        while page_retry_count <= max_page_retries:
            start = i * 10
            params = base_params.copy()
            params["q"] = query
            params["start"] = str(start)
            params["callback"] = f"google.search.cse.api{start}"

            # Add delay between requests for Docker Tor stability
            if i > 0 or page_retry_count > 0:
                delay = 2.0 if page_retry_count == 0 else 3.0 * page_retry_count
                print(f"[WAIT] Waiting {delay:.1f} seconds before request...")
                time.sleep(delay)
            
            # Verify Tor connection before making request
            if not check_tor_connection(verbose=True):
                print(f"[WARNING] Tor connection not available (host={TOR_SOCKS_HOST}, port={TOR_SOCKS_PORT}), attempting restart...")
                if restart_docker_tor():
                    # Wait a bit more after restart
                    print("[DOCKER] Additional wait after restart...")
                    time.sleep(5)
                    
                    # Reinitialize Tor connection after restart
                    reinitialize_tor_connection()
                    
                    # Verify connection again after restart with multiple attempts
                    connection_verified = False
                    for verify_attempt in range(3):
                        if check_tor_connection(verbose=True):
                            print(f"[OK] Tor connection verified after restart (attempt {verify_attempt + 1})")
                            connection_verified = True
                            break
                        else:
                            print(f"[WARNING] Connection check {verify_attempt + 1}/3 failed, waiting...")
                            time.sleep(3)
                    
                    if not connection_verified:
                        print(f"[WARNING] Tor connection still not available after restart, but continuing with retry...")
                    
                    page_retry_count += 1
                    continue
                else:
                    print(f"[ERROR] Tor connection failed and restart failed")
                    if page_retry_count < max_page_retries:
                        page_retry_count += 1
                        time.sleep(5)
                        continue
                    else:
                        results = []
                        break
            
            # Try to fetch with error handling and Docker restart (Solution 1)
            try:
                # Use longer timeout for Docker environment
                response = rt.get(url, params=params, timeout=60)
                if response.status_code != 200:
                    print(f"[WARNING] Non-200 status code: {response.status_code}, retrying...")
                    response = retry_request(url, params)
            except Exception as conn_error:
                # Solution 1: Restart Docker Tor on connection failures
                error_msg = str(conn_error)
                print(f"{platform_name} Connection error on page {i+1}: {error_msg[:150]}")
                
                # Restart Docker Tor on connection errors (especially on first few retries)
                if page_retry_count < 2:  # Restart on first 2 failures
                    print("[SOLUTION 1] Attempting to restart Docker Tor container...")
                    if restart_docker_tor():
                        # Reinitialize Tor connection after restart
                        reinitialize_tor_connection()
                        print("[SOLUTION 1] Docker Tor restarted, retrying request...")
                        page_retry_count += 1
                        continue
                    else:
                        print("[SOLUTION 1] Docker Tor restart failed, trying normal retry...")
                
                # Normal retry logic with exponential backoff
                if page_retry_count < max_page_retries:
                    wait_time = min((page_retry_count + 1) * 3, 15)  # Max 15 seconds
                    print(f"{platform_name} Retrying in {wait_time} seconds... (attempt {page_retry_count + 1}/{max_page_retries})")
                    time.sleep(wait_time)
                    page_retry_count += 1
                    continue
                else:
                    print(f"{platform_name} Failed after {max_page_retries} retries, skipping page {i+1}...")
                    results = []
                    break
            
            raw_text = response.text

            match = re.search(r'google\.search\.cse\.\w+\((.*)\);', raw_text, re.S)
            if not match:
                print(f"{platform_name} page {i+1} failed, response:\n{raw_text[:200]}...\n")
                # For TikTok/Pinterest, check if response contains error or empty results
                if platform_name.upper() in ["TIKTOK", "PINTEREST"]:
                    print(f"[DEBUG] {platform_name} response length: {len(raw_text)}")
                    if "error" in raw_text.lower() or "no results" in raw_text.lower():
                        print(f"[DEBUG] {platform_name} may have no results or error in response")
                break  # If parsing fails, skip to next page directly

            json_str = match.group(1)
            try:
                data = json.loads(json_str)
                results = data.get("results", [])
                
                # Print cursor information with search total count (only once)
                if "cursor" in data and not cursor_printed:
                    cursor = data.get("cursor", {})
                    # Print search total from cursor
                    result_count = None
                    if "resultCount" in cursor:
                        result_count = cursor['resultCount']
                        print(f"[CURSOR] {platform_name} Search total count: {result_count}")
                    elif "estimatedResultCount" in cursor:
                        result_count = cursor['estimatedResultCount']
                        print(f"[CURSOR] {platform_name} Estimated search total: {result_count}")
                    # Print full cursor info
                    print(f"[CURSOR] {platform_name} Full cursor info: {cursor}")
                    cursor_printed = True
                    
                    # If resultCount < 100, adjust pages based on resultCount // 10
                    # Convert result_count to int if it's a string
                    if result_count is not None:
                        try:
                            # Remove commas and other non-numeric characters before converting to int
                            if isinstance(result_count, str):
                                # Remove commas, spaces, and other formatting characters
                                result_count_clean = result_count.replace(',', '').replace(' ', '').strip()
                                result_count_int = int(result_count_clean)
                            else:
                                result_count_int = int(result_count)
                            if result_count_int < 100:
                                new_pages = result_count_int // 10
                                if new_pages > 0:
                                    max_pages = new_pages
                                    print(f"[PAGES] {platform_name} Adjusted pages from {pages} to {max_pages} (based on resultCount: {result_count_int})")
                                else:
                                    max_pages = 1  # At least 1 page
                                    print(f"[PAGES] {platform_name} Adjusted pages to 1 (resultCount: {result_count_int} < 10)")
                        except (ValueError, TypeError) as e:
                            print(f"[WARNING] {platform_name} Failed to convert resultCount to int: {result_count}, error: {e}")
                
                # Debug for TikTok/Pinterest
                if platform_name.upper() in ["TIKTOK", "PINTEREST"] and len(results) == 0:
                    print(f"[DEBUG] {platform_name} page {i+1}: Parsed successfully but got 0 results")
                    print(f"[DEBUG] Response data keys: {list(data.keys())}")
            except json.JSONDecodeError as e:
                print(f"{platform_name} page {i+1} JSON decode error: {e}")
                print(f"JSON string (first 500 chars): {json_str[:500]}")
                results = []

            # Check if the number of results is not equal to 10
            # Solution 1: Restart Docker Tor instead of identity switching
            if len(results) != 10 and page_retry_count < 2:  # Allow retry on first 2 attempts
                print(f"Warning: Expected 10 results but got {len(results)} results. Triggering Docker Tor restart (Solution 1)...")
                if restart_docker_tor():
                    # Reinitialize Tor connection after restart
                    reinitialize_tor_connection()
                    print("[SOLUTION 1] Docker Tor restarted, retrying page with fresh connection...")
                    page_retry_count += 1
                    continue  # Re-fetch current page
                else:
                    # If restart fails, use current results if we have some
                    if len(results) > 0:
                        print(f"Docker restart failed, using current results ({len(results)} records)")
                        break
                    else:
                        # No results, try one more time
                        if page_retry_count < max_page_retries:
                            page_retry_count += 1
                            time.sleep(3)
                            continue
                        break
            else:
                # Results are normal or already retried, use current results
                print(f"{platform_name} Got page {i+1}, total {len(results)} records")
                if page_retry_count > 0:
                    print(f"Successfully retrieved full results after retry!")
                break
        
        # Add results to total results (regardless of completeness)
        all_results.extend(results)

        if len(all_results) >= num:
            break
        
        i += 1  # Increment page counter

    return all_results[:num]

def retry_request(url, params, max_retries=3):
    """Retry request with exponential backoff"""
    global rt
    last_response = None
    for attempt in range(max_retries):
        try:
            print(f"Retrying... attempt {attempt + 1}/{max_retries}")
            if attempt > 0:
                time.sleep(attempt * 3)  # Exponential backoff
            # Verify Tor connection before retry
            if not check_tor_connection():
                print("[WARNING] Tor connection lost during retry, restarting...")
                if restart_docker_tor():
                    reinitialize_tor_connection()
                    time.sleep(2)
            response = rt.get(url, params=params, timeout=60)  # Increased timeout
            last_response = response
            if response.status_code == 200:
                return response
        except Exception as e:
            error_msg = str(e)
            print(f"Retry attempt {attempt + 1} failed: {error_msg[:150]}")
            if attempt == max_retries - 1:
                if last_response:
                    return last_response
                # Last attempt failed, try restarting Tor one more time
                if "SOCKS" in error_msg.upper() or "Connection" in error_msg:
                    print("[LAST RESORT] Attempting Tor restart before final failure...")
                    if restart_docker_tor():
                        reinitialize_tor_connection()
                        time.sleep(3)
                        try:
                            response = rt.get(url, params=params, timeout=60)
                            return response
                        except:
                            pass
                raise
    
    return last_response if last_response else None
    

def convert_relative_time_to_datetime(time_str):
    """
    Convert relative time string to actual datetime
    
    Args:
        time_str (str): Time string like "6 hours ago", "2 days ago", "12-Oct-25", etc.
        
    Returns:
        str: Formatted datetime string (YYYY-MM-DD HH:MM:SS) or current datetime if parsing fails
    """
    if not time_str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    now = datetime.now()
    original_str = time_str
    time_str = time_str.lower().strip()
    
    # Month mappings
    month_map_abbr = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'sept': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    
    month_map_full = {
        'january': 1, 'february': 2, 'march': 3, 'april': 4, 'may': 5, 'june': 6,
        'july': 7, 'august': 8, 'september': 9, 'october': 10, 'november': 11, 'december': 12
    }
    
    # Handle special cases first
    if time_str in ["just now", "now"]:
        return now.strftime("%Y-%m-%d %H:%M:%S")
    elif time_str == "today":
        return now.strftime("%Y-%m-%d 00:00:00")
    elif time_str == "yesterday":
        return (now - timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    
    # Handle absolute date formats with various separators
    # DD MMM YYYY format like "12 Oct 2025" (4-digit year first, higher priority)
    dd_mmm_yyyy_match = re.search(r'(\d{1,2})[-\s](jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[-\s](\d{4})', time_str)
    if dd_mmm_yyyy_match:
        day, month_abbr, year = dd_mmm_yyyy_match.groups()
        try:
            month_num = month_map_abbr[month_abbr]
            result_date = datetime(int(year), month_num, int(day))
            return result_date.strftime("%Y-%m-%d 00:00:00")
        except (ValueError, KeyError):
            pass
    
    # DD-MMM-YY format like "12-Oct-25" or "12 Oct 25" (2-digit year, lower priority)
    dd_mmm_yy_match = re.search(r'(\d{1,2})[-\s](jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[-\s](\d{2})(?!\d)', time_str)
    if dd_mmm_yy_match:
        day, month_abbr, year = dd_mmm_yy_match.groups()
        try:
            month_num = month_map_abbr[month_abbr]
            # Convert 2-digit year to 4-digit (assuming 2000s)
            full_year = 2000 + int(year)
            result_date = datetime(full_year, month_num, int(day))
            return result_date.strftime("%Y-%m-%d 00:00:00")
        except (ValueError, KeyError):
            pass
    
    # DD-Month-YYYY format like "12-October-2025" or "12 October 2025"
    dd_month_yyyy_match = re.search(r'(\d{1,2})[-\s](january|february|march|april|may|june|july|august|september|october|november|december)[-\s](\d{4})', time_str)
    if dd_month_yyyy_match:
        day, month_name, year = dd_month_yyyy_match.groups()
        try:
            month_num = month_map_full[month_name]
            result_date = datetime(int(year), month_num, int(day))
            return result_date.strftime("%Y-%m-%d 00:00:00")
        except (ValueError, KeyError):
            pass
    
    # MMM DD, YYYY format like "Oct 12, 2025" or "October 12, 2025"
    mmm_dd_yyyy_match = re.search(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec|january|february|march|april|may|june|july|august|september|october|november|december)[a-z]*[,\s]+(\d{1,2})[,\s]+(\d{4})', time_str)
    if mmm_dd_yyyy_match:
        month_str, day, year = mmm_dd_yyyy_match.groups()
        try:
            month_num = month_map_abbr.get(month_str, month_map_full.get(month_str))
            if month_num:
                result_date = datetime(int(year), month_num, int(day))
                return result_date.strftime("%Y-%m-%d 00:00:00")
        except (ValueError, KeyError):
            pass
    
    # YYYY-MM-DD format (ISO format)
    yyyy_mm_dd_match = re.search(r'(\d{4})[-/](\d{1,2})[-/](\d{1,2})', original_str)
    if yyyy_mm_dd_match:
        year, month, day = yyyy_mm_dd_match.groups()
        try:
            result_date = datetime(int(year), int(month), int(day))
            return result_date.strftime("%Y-%m-%d 00:00:00")
        except ValueError:
            pass
    
    # MM/DD/YYYY or DD/MM/YYYY format
    slash_date_match = re.search(r'(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})', original_str)
    if slash_date_match:
        part1, part2, year = slash_date_match.groups()
        # Try MM/DD/YYYY format first (US format)
        try:
            if int(part1) <= 12 and int(part2) <= 31:
                result_date = datetime(int(year), int(part1), int(part2))
                return result_date.strftime("%Y-%m-%d 00:00:00")
        except ValueError:
            pass
        # Try DD/MM/YYYY format (European format)
        try:
            if int(part2) <= 12 and int(part1) <= 31:
                result_date = datetime(int(year), int(part2), int(part1))
                return result_date.strftime("%Y-%m-%d 00:00:00")
        except ValueError:
            pass

    # Parse relative time expressions
    patterns = {
        # Standard forms
        r'(\d+)\s+seconds?\s+ago': lambda n: now - timedelta(seconds=int(n)),
        r'(\d+)\s+minutes?\s+ago': lambda n: now - timedelta(minutes=int(n)),
        r'(\d+)\s+hours?\s+ago': lambda n: now - timedelta(hours=int(n)),
        r'(\d+)\s+days?\s+ago': lambda n: now - timedelta(days=int(n)),
        r'(\d+)\s+weeks?\s+ago': lambda n: now - timedelta(weeks=int(n)),
        r'(\d+)\s+months?\s+ago': lambda n: now - timedelta(days=int(n)*30),
        r'(\d+)\s+years?\s+ago': lambda n: now - timedelta(days=int(n)*365),
        
        # Short forms
        r'(\d+)\s*s\s+ago': lambda n: now - timedelta(seconds=int(n)),
        r'(\d+)\s*m\s+ago': lambda n: now - timedelta(minutes=int(n)),
        r'(\d+)\s*h\s+ago': lambda n: now - timedelta(hours=int(n)),
        r'(\d+)\s*d\s+ago': lambda n: now - timedelta(days=int(n)),
        r'(\d+)\s*w\s+ago': lambda n: now - timedelta(weeks=int(n)),
        r'(\d+)\s+secs?\s+ago': lambda n: now - timedelta(seconds=int(n)),
        r'(\d+)\s+mins?\s+ago': lambda n: now - timedelta(minutes=int(n)),
        r'(\d+)\s+hrs?\s+ago': lambda n: now - timedelta(hours=int(n)),
        
        # "a/an" forms
        r'an?\s+second\s+ago': lambda n: now - timedelta(seconds=1),
        r'an?\s+minute\s+ago': lambda n: now - timedelta(minutes=1),
        r'an?\s+hour\s+ago': lambda n: now - timedelta(hours=1),
        r'an?\s+day\s+ago': lambda n: now - timedelta(days=1),
        r'an?\s+week\s+ago': lambda n: now - timedelta(weeks=1),
        r'an?\s+month\s+ago': lambda n: now - timedelta(days=30),
        r'an?\s+year\s+ago': lambda n: now - timedelta(days=365),
        
        # Variations without "ago"
        r'(\d+)\s+seconds?\s+before': lambda n: now - timedelta(seconds=int(n)),
        r'(\d+)\s+minutes?\s+before': lambda n: now - timedelta(minutes=int(n)),
        r'(\d+)\s+hours?\s+before': lambda n: now - timedelta(hours=int(n)),
        r'(\d+)\s+days?\s+before': lambda n: now - timedelta(days=int(n)),
    }
    
    for pattern, calc_func in patterns.items():
        match = re.search(pattern, time_str)
        if match:
            try:
                if 'an?' in pattern:
                    result_time = calc_func(1)
                else:
                    result_time = calc_func(match.group(1))
                return result_time.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OverflowError):
                continue
    
    # If no pattern matches, try to parse as a timestamp or return current time
    try:
        # Try parsing as timestamp (seconds since epoch)
        if time_str.isdigit() and len(time_str) >= 10:
            timestamp = int(time_str)
            result_time = datetime.fromtimestamp(timestamp)
            return result_time.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError):
        pass
    
    # If all parsing fails, return current datetime with a note
    print(f"Warning: Could not parse time '{original_str}', using current time")
    return now.strftime("%Y-%m-%d %H:%M:%S")

def extract_date_from_abstract(abstract):
    """
    Extract date information from abstract text (first 3 words) and convert to datetime
    
    Args:
        abstract (str): The abstract content
        
    Returns:
        tuple: (formatted_datetime, cleaned_abstract) where formatted_datetime is the converted datetime and cleaned_abstract is the text without the first 3 words
    """
    if not abstract:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""
    
    # Split the abstract into words
    words = abstract.split()
    
    # Take the first 3 words as date string
    if len(words) >= 3:
        date_string = ' '.join(words[:3])
       
        # Remove the first 3 words from abstract
        cleaned_abstract = ' '.join(words[4:]).strip()
    else:
        # If less than 3 words, use the entire abstract as date string
        date_string = abstract
        cleaned_abstract = ""
    
    # Convert the date string to datetime
    converted_time = convert_relative_time_to_datetime(date_string)
    
    # If conversion failed, use current time
    if not converted_time:
        converted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Ensure cleaned_abstract is not empty, if so use original
    if not cleaned_abstract:
        cleaned_abstract = abstract
    
    return converted_time, cleaned_abstract

def stop_docker_containers():
    """Stop and remove Docker containers (specifically docker-tor)"""
    print("[SHUTDOWN] Stopping Docker containers...")
    containers_to_stop = ["docker-tor"]
    
    # First, try to use docker-compose down (most reliable way)
    try:
        compose_paths = [
            Path("/app/../docker-compose.yml"),  # Parent directory (mounted volume)
            Path("/app/docker-compose.yml"),  # Inside container
            Path.cwd() / "docker-compose.yml",  # Current directory
        ]
        
        compose_file = None
        for path in compose_paths:
            if path.exists():
                compose_file = path
                break
        
        if compose_file:
            print(f"[SHUTDOWN] Using docker-compose down from {compose_file.parent}")
            # Try Docker Compose V2 first (docker compose), then V1 (docker-compose) for compatibility
            for cmd in [['docker', 'compose', '-f', str(compose_file), 'down'], 
                        ['docker-compose', '-f', str(compose_file), 'down']]:
                try:
                    result = subprocess.run(
                        cmd,
                        cwd=compose_file.parent,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        print("[SHUTDOWN] docker-compose down completed successfully")
                        if result.stdout:
                            print(f"[SHUTDOWN] {result.stdout.strip()}")
                        return  # Success, exit early
                    else:
                        # Try next command
                        continue
                except FileNotFoundError:
                    # Command not found, try next
                    continue
                except Exception as e:
                    print(f"[SHUTDOWN] Error with {' '.join(cmd)}: {str(e)}")
                    continue
            
            print("[SHUTDOWN] Both docker-compose commands failed, falling back to individual stop")
    except Exception as e:
        print(f"[SHUTDOWN] docker-compose down error: {str(e)}")
    
    # Fallback: Stop and remove containers individually
    print("[SHUTDOWN] Falling back to individual container stop/remove")
    
    for container_name in containers_to_stop:
        try:
            # Check if container exists (running or stopped)
            check_result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if container_name in check_result.stdout:
                # Container exists, stop it first
                print(f"[SHUTDOWN] Stopping container: {container_name}")
                stop_result = subprocess.run(
                    ['docker', 'stop', container_name],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if stop_result.returncode == 0:
                    print(f"[SHUTDOWN] Container {container_name} stopped")
                    
                    # Remove the container
                    print(f"[SHUTDOWN] Removing container: {container_name}")
                    remove_result = subprocess.run(
                        ['docker', 'rm', container_name],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if remove_result.returncode == 0:
                        print(f"[SHUTDOWN] Container {container_name} removed successfully")
                    else:
                        print(f"[SHUTDOWN] Remove failed: {remove_result.stderr.strip()}")
                else:
                    print(f"[SHUTDOWN] Stop failed: {stop_result.stderr.strip()}")
            else:
                print(f"[SHUTDOWN] Container {container_name} does not exist")
                
        except subprocess.TimeoutExpired:
            print(f"[SHUTDOWN] Timeout while processing {container_name}")
        except Exception as e:
            print(f"[SHUTDOWN] Error processing {container_name}: {str(e)}")
    
    print("[SHUTDOWN] All containers shutdown and removal process completed")
    # Small delay to ensure stop operations complete
    time.sleep(2)


def save_to_csv(results, keyword, platform, filename=None, output_path=None):
    """
    Save results to CSV file using output/keyword/ directory structure
    
    Args:
        results: Search results
        keyword: Search keyword
        platform: Platform name (facebook, twitter, instagram, linkedin)
        filename: Optional custom filename
        output_path: Optional custom output directory path
    """
    # Use custom output path if provided, otherwise use default output/keyword/
    if output_path:
        output_dir = Path(output_path) / keyword
        print(f"[DEBUG] Using custom output path: {output_path}")
    else:
        output_dir = Path("output") / keyword
        print(f"[DEBUG] Using default output path: output/")
    print(f"[DEBUG] Output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    if filename is None:
        filename = f"{keyword}_{platform}.csv"
    
    filepath = output_dir / filename
    print(f"[DEBUG] Saving to: {filepath}")
    
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["title", "url", "abstract", "date"])
        for r in results:
            original_abstract = r.get("contentNoFormatting", "")
            date_info, cleaned_abstract = extract_date_from_abstract(original_abstract)
            
            writer.writerow([
                r.get("titleNoFormatting", ""),
                r.get("url", ""),
                cleaned_abstract,
                date_info
            ])
    
    print(f"Saved to {filepath}")
    return str(filepath)



def search_all_platforms(query, total_num=100, updated_params=None, output_path=None):
    """
    Execute search on all platforms
    
    Args:
        query (str): Search keyword
        total_num (int): Number of results per platform
        updated_params (dict): Updated parameters, can be:
                              - General parameters dictionary
                              - Dictionary containing platform parameters {"facebook": {...}, "twitter": {...}}
        output_path (str): Optional custom output directory path
    """
    global rt  # Declare global rt at the beginning
    results = {}
    
    platforms = ["facebook", "twitter", "instagram", "linkedin", "tiktok", "pinterest"]
    
    print(f"Starting search on {len(platforms)} platforms for '{query}'...")
    print(f"Target results per platform: {total_num}")
    print("-" * 50)
    
    for platform in platforms:
        print(f"\n[SEARCH] Starting {platform.upper()} search...")
        
        max_platform_retries = 3  # Maximum retries for each platform
        platform_retry_count = 0
        
        while platform_retry_count <= max_platform_retries:
            try:
                base_params = get_base_params(platform, updated_params)
                
                # Display current key parameters
                print(f"   CSE ID (cx): {base_params.get('cx', 'N/A')}")
                print(f"   CSE Token: {base_params.get('cse_tok', 'N/A')[:50]}...")
                
                platform_results = fetch_google_cse(query, base_params, num=total_num, platform_name=platform.upper())
                
                # Solution 1: Check if results are less than expected, restart Docker and retry
                if len(platform_results) < total_num and platform_retry_count < max_platform_retries:
                    print(f"[SOLUTION 1] Got {len(platform_results)} results, expected {total_num}. Restarting Docker Tor and retrying...")
                    if restart_docker_tor():
                        reinitialize_tor_connection()
                        platform_retry_count += 1
                        print(f"[SOLUTION 1] Retrying {platform.upper()} search (attempt {platform_retry_count + 1}/{max_platform_retries})...")
                        time.sleep(5)  # Wait before retry
                        continue
                    else:
                        print(f"[SOLUTION 1] Docker restart failed, using current results")
                        break
                
                # Results are acceptable (either full or max retries reached)
                results[platform] = platform_results
                
                # Save to CSV (using new directory structure)
                filepath = save_to_csv(platform_results, query, platform, output_path=output_path)
                
                if len(platform_results) < total_num:
                    print(f"[WARNING] {platform.upper()} search completed with {len(platform_results)} results (expected {total_num})")
                else:
                    print(f"[OK] {platform.upper()} search completed, got {len(platform_results)} results")
                
                # After saving output, continue to next platform
                print(f"[INFO] {platform.upper()} output saved, proceeding to next platform...")
                
                # If this is pinterest (last platform), stop containers
                if platform == "pinterest":
                    print(f"[SHUTDOWN] Pinterest search completed, stopping Docker containers...")
                    stop_docker_containers()
                
                break  # Success, exit retry loop
                
            except Exception as e:
                error_msg = str(e)
                print(f"[ERROR] {platform.upper()} search failed: {error_msg[:200]}")
                
                # Solution 1: Restart Docker on any error
                if platform_retry_count < max_platform_retries:
                    print(f"[SOLUTION 1] Restarting Docker Tor due to error, retrying...")
                    if restart_docker_tor():
                        reinitialize_tor_connection()
                        platform_retry_count += 1
                        print(f"[SOLUTION 1] Retrying {platform.upper()} search (attempt {platform_retry_count + 1}/{max_platform_retries})...")
                        time.sleep(5)  # Wait before retry
                        continue
                    else:
                        print(f"[SOLUTION 1] Docker restart failed")
                        results[platform] = []
                        # If this is pinterest and we're giving up, stop containers
                        if platform == "pinterest":
                            print(f"[SHUTDOWN] Pinterest search failed, stopping Docker containers...")
                            stop_docker_containers()
                        break
                else:
                    # Max retries reached
                    print(f"[ERROR] {platform.upper()} search failed after {max_platform_retries} retries")
                    results[platform] = []
                    # If this is pinterest and we're giving up, stop containers
                    if platform == "pinterest":
                        print(f"[SHUTDOWN] Pinterest search failed after retries, stopping Docker containers...")
                        stop_docker_containers()
                    break
    
    print(f"\n{'='*50}")
    print("Search Summary:")
    total_results = 0
    for platform, platform_results in results.items():
        count = len(platform_results)
        total_results += count
        print(f"  {platform.upper()}: {count} results")
    print(f"Total: {total_results} results")
    
    return results

if __name__ == "__main__":
    
    # The search query keyword or domain
    query = "natixis"
    # The maximum number of results to fetch
    total_num = 100

    search_all_platforms(query, total_num)
