#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Optional

import pandas as pd
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator

# ASCII Banner
BANNER = r"""

 ▄▄▄▄    ██▀███   ▄▄▄       ███▄    █ ▓█████▄      ██████  ▄████▄   ▒█████   █    ██ ▄▄▄█████▓
▓█████▄ ▓██ ▒ ██▒▒████▄     ██ ▀█   █ ▒██▀ ██▌   ▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒ ██  ▓██▒▓  ██▒ ▓▒
▒██▒ ▄██▓██ ░▄█ ▒▒██  ▀█▄  ▓██  ▀█ ██▒░██   █▌   ░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒▓██  ▒██░▒ ▓██░ ▒░
▒██░█▀  ▒██▀▀█▄  ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█▄   ▌     ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░▓▓█  ░██░░ ▓██▓ ░ 
░▓█  ▀█▓░██▓ ▒██▒ ▓█   ▓██▒▒██░   ▓██░░▒████▓    ▒██████▒▒▒ ▓███▀ ░░ ████▓▒░▒▒█████▓   ▒██▒ ░ 
░▒▓███▀▒░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░▒▓▒ ▒ ▒   ▒ ░░   
▒░▒   ░   ░▒ ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░ ░░▒░ ░ ░     ░    
 ░    ░   ░░   ░   ░   ▒      ░   ░ ░  ░ ░  ░    ░  ░  ░  ░        ░ ░ ░ ▒   ░░░ ░ ░   ░      
 ░         ░           ░  ░         ░    ░             ░  ░ ░          ░ ░     ░              
      ░                                ░                  ░                                   
                                                          
                     Brand Abuse Protection & Intelligence Gathering
"""

def print_banner():
    print(BANNER)

def run_command(command: List[str], cwd: Optional[str] = None):
    """Runs a shell command and lets it stream output directly to TTY."""
    try:
        # Use subprocess.run to allow direct TTY inheritance.
        # This fixes buffering and carriage return issues (progress bars).
        result = subprocess.run(command, cwd=cwd)
        if result.returncode != 0:
            print(f"Error: Command failed with exit code {result.returncode}")
            return False
        return True
    except Exception as e:
        print(f"Error executing command: {e}")
        return False

def _repo_root() -> str:
    """Directory containing ``brand_scout.py`` (works on host and in Docker when layout matches)."""
    return os.path.dirname(os.path.abspath(__file__))


def _fqdn_for_permutations(domain: str) -> str:
    """
    dnstwist / permutation tools expect a registrable FQDN (e.g. ``lalamove.com``), not a bare brand name.
    If the input has no dot, append ``.com`` and warn (override in UI with the correct TLD if needed).
    """
    d = domain.strip()
    if not d or "." in d:
        return d
    suggested = f"{d}.com"
    print(
        f"[!] Domain '{d}' has no dot (not a FQDN). Using '{suggested}' for permutation tools; "
        "pass the real domain (e.g. lalamove.in) if different."
    )
    return suggested


def run_phishing_scan(domain: str, start_date: str, end_date: str):
    """Runs the Phishing Scan (PS) logic."""
    domain = _fqdn_for_permutations(domain)
    print(f"\n[*] Starting Phishing Scan for {domain}...")

    # Create directory for the domain
    domain_dir = os.path.join(os.getcwd(), domain)
    os.makedirs(domain_dir, exist_ok=True)

    cmd = [
        "docker", "run", "--rm"
    ]
    
    if sys.stdout.isatty():
        cmd.append("-it")
        
    cmd.extend([
        "-v", f"{domain_dir}:/workdir",
        "br0k3nm1rr0r/domain-sift",
        domain,
        "30"
    ])
    
    if not run_command(cmd):
        print("[-] Domain sift failed.")
        return

    # 2. Filter results
    permutations_lookup_path = os.path.join(domain_dir, f"{domain}_permutations_lookup.csv")
    if not os.path.exists(permutations_lookup_path):
        print(f"[-] {permutations_lookup_path} not found.")
        return

    print(f"[*] Filtering results between {start_date} and {end_date}...")
    
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")

        filtered_rows = []
        
        with open(permutations_lookup_path, mode='r', encoding='utf-8', errors='replace') as infile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames
            
            for row in reader:
                whois_info = row.get("WHOIS Info", "")
                # "RDAP Source: ... Registration: 2004-05-17T18:31:39Z ..."
                # regex for "Registration: YYYY-MM-DD" 
                # Example: Registration: 2004-05-17T18:31:39Z
                import re
                match = re.search(r"Registration:\s*(\d{4}-\d{2}-\d{2})", whois_info)
                if match:
                    reg_date_str = match.group(1)
                    try:
                        reg_date = datetime.strptime(reg_date_str, "%Y-%m-%d")
                        if start_dt <= reg_date <= end_dt:
                            filtered_rows.append(row)
                    except ValueError:
                        pass # Date parse error
        
        # Save filtered results
        if filtered_rows:
            out_path = os.path.join(domain_dir, f"{domain}_phish_results.csv")
            with open(out_path, mode='w', encoding='utf-8', newline='') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(filtered_rows)
            print(f"[+] Saved {len(filtered_rows)} records to {out_path}")
        else:
            print("[-] No records matched the date range.")

    except Exception as e:
        print(f"[-] Error processing CSV: {e}")

def run_social_media_scan(keyword: str, start_date: str, end_date: str):
    """Runs the Social Media Scan (SMS) logic."""
    print(f"\n[*] Starting Social Media Scan for '{keyword}'...")

    script_path = os.path.join(_repo_root(), "social_media", "docker-run.sh")
    if not os.path.isfile(script_path):
        print(f"[-] Social media launcher not found: {script_path}")
        return
    # make sure it's executable (no-op on Windows hosts)
    try:
        os.chmod(script_path, 0o755)
    except OSError as e:
        print(f"[!] Could not chmod docker-run.sh (continuing): {e}")
    
    # set output path to something in /workdir.
    output_path = os.path.join(os.getcwd(), "social_media_output")
    os.makedirs(output_path, exist_ok=True)
    
    cmd = [
        script_path,
        keyword,
        output_path,
        start_date,
        end_date
    ]
    
    print(f"[*] Executing: {' '.join(cmd)}")
    social_media_cwd = os.path.join(_repo_root(), "social_media")
    if not run_command(cmd, cwd=social_media_cwd):
        print("[-] Social media scan failed.")

def take_screenshots_logic():
    """Extracts domains/URLs and runs the screenshot tool."""
    print("\n[*] Starting Screenshot process...")
    
    # 1. Domains from phish_results.csv
    phish_csvs = glob.glob("**/*_phish_results.csv", recursive=True)
    domains_to_snap = []
    
    if phish_csvs:
        for phish_csv in phish_csvs:
            try:
                with open(phish_csv, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        domain = row.get("Domain")
                        if domain:
                            # Normalize domain to url
                            if not (domain.startswith("http://") or domain.startswith("https://")):
                                url = f"http://{domain}"
                            else:
                                url = domain
                            domains_to_snap.append(url)
            except Exception as e:
                print(f"[-] Error reading {phish_csv}: {e}")
    else:
        print("[-] No phish_results.csv files found, skipping domain screenshots.")

    # 2. URLs from social media outputs
    sm_output_dir = "social_media_output"
    
    screenshots_input_dir = "screenshots_job"
    os.makedirs(screenshots_input_dir, exist_ok=True)
    
    # Write domain URLs to CSV
    if domains_to_snap:
        with open(os.path.join(screenshots_input_dir, "phishing_domains.csv"), 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["url"]) # Header required
            for d in domains_to_snap:
                writer.writerow([d])
    
    # extract social media URLs into separate CSVs with only 'url' column
    if os.path.exists(sm_output_dir):
         csv_files = glob.glob(f"{sm_output_dir}/**/*.csv", recursive=True)
         for i, cf in enumerate(csv_files):
             urls_to_snap = []
             try:
                 with open(cf, 'r', encoding='utf-8') as f:
                     reader = csv.DictReader(f)
                     if "url" in reader.fieldnames:
                         for row in reader:
                             u = row.get("url")
                             if u:
                                 urls_to_snap.append(u)
             except Exception as e:
                 print(f"[-] Error reading {cf}: {e}")
                 
             if urls_to_snap:
                 base_name = os.path.basename(cf)
                 out_name = os.path.join(screenshots_input_dir, f"sm_{i}_{base_name}")
                 with open(out_name, 'w', newline='', encoding='utf-8') as f:
                     writer = csv.writer(f)
                     writer.writerow(["url"])
                     for u in urls_to_snap:
                         writer.writerow([u])

    screenshots_pkg = os.path.join(_repo_root(), "screenshots")
    if os.path.isdir(screenshots_pkg):
        sys.path.insert(0, screenshots_pkg)
    else:
        print(f"[-] Screenshots package not found: {screenshots_pkg}")

    try:
        from screenshots_script import run_folder

        # ./screenshots_output: a directory containing screenshots of all domains and urls
        output_root = run_folder(screenshots_input_dir, output_root=os.path.abspath("screenshots_output"), headless=True)
        print(f"[+] Screenshots saved to {output_root}")

    except ImportError:
        print(
            f"[-] Could not import screenshot tool. Expected a 'screenshots' folder "
            f"next to brand_scout.py: {screenshots_pkg}"
        )
    except Exception as e:
        print(f"[-] Screenshot tool error: {e}")

    # Cleanup
    # shutil.rmtree(screenshots_input_dir) # Optional

from prompt_toolkit.validation import ValidationError

def validate_date(date_text):
    """Validates that the input is in YYYY-MM-DD format and is a valid date."""
    try:
        if not date_text:
            raise ValueError
        datetime.strptime(date_text, "%Y-%m-%d")
        return True
    except ValueError:
        raise ValidationError(message="Please enter a valid date in YYYY-MM-DD format.")

def main():
    parser = argparse.ArgumentParser(description="Brand Scout Tool")
    parser.add_argument("-all", nargs=4, metavar=('DOMAIN', 'KEYWORD', 'START', 'END'), help="Run ALL scans in non-interactive mode")
    parser.add_argument("-ps", nargs=3, metavar=('DOMAIN', 'START', 'END'), help="Run Phishing Scan in non-interactive mode")
    parser.add_argument("-sms", nargs=3, metavar=('KEYWORD', 'START', 'END'), help="Run Social Media Scan in non-interactive mode")
    
    args = parser.parse_args()
    
    print_banner()
    
    mode = None
    domain_input = None
    keyword_input = None
    start_date = None
    end_date = None

    if args.all:
        mode = "ALL"
        domain_input = args.all[0]
        keyword_input = args.all[1]
        start_date = args.all[2]
        end_date = args.all[3]
        
        # Basic validation for CLI args
        if validate_date(start_date) is not True or validate_date(end_date) is not True:
             print("[-] Invalid date format in arguments. Please use YYYY-MM-DD.")
             sys.exit(1)

        print(f"[*] Running in Non-Interactive Mode: ALL")
        print(f"    Domain(s): {domain_input}")
        print(f"    Keyword(s): {keyword_input}")
        print(f"    Timeframe: {start_date} to {end_date}")
    elif args.ps:
        mode = "PS"
        domain_input = args.ps[0]
        start_date = args.ps[1]
        end_date = args.ps[2]
        
        # Basic validation for CLI args
        if validate_date(start_date) is not True or validate_date(end_date) is not True:
             print("[-] Invalid date format in arguments. Please use YYYY-MM-DD.")
             sys.exit(1)

        print(f"[*] Running in Non-Interactive Mode: PS")
        print(f"    Domain(s): {domain_input}")
        print(f"    Timeframe: {start_date} to {end_date}")
    elif args.sms:
        mode = "SMS"
        keyword_input = args.sms[0]
        start_date = args.sms[1]
        end_date = args.sms[2]
        
        # Basic validation for CLI args
        if validate_date(start_date) is not True or validate_date(end_date) is not True:
             print("[-] Invalid date format in arguments. Please use YYYY-MM-DD.")
             sys.exit(1)

        print(f"[*] Running in Non-Interactive Mode: SMS")
        print(f"    Keyword(s): {keyword_input}")
        print(f"    Timeframe: {start_date} to {end_date}")
    else:
        # Interactive Mode
        choice = inquirer.select(
            message="Select Scan Type:",
            choices=["PS (Phishing Scan)", "SMS (Social Media Scan)", "ALL (Both Scans)"],
        ).execute()
        
        if "PS" in choice:
            mode = "PS"
        elif "SMS" in choice:
            mode = "SMS"
        else:
            mode = "ALL"
            
        # Ask details
        if mode == "PS":
            domain_input = inquirer.text(message="Enter Domain(s), comma-separated:").execute()
            start_date = inquirer.text(message="Start Date (YYYY-MM-DD):", validate=validate_date).execute()
            end_date = inquirer.text(message="End Date (YYYY-MM-DD):", validate=validate_date).execute()
        elif mode == "SMS":
            keyword_input = inquirer.text(message="Enter Keyword(s), comma-separated:").execute()
            start_date = inquirer.text(message="Start Date (YYYY-MM-DD):", validate=validate_date).execute()
            end_date = inquirer.text(message="End Date (YYYY-MM-DD):", validate=validate_date).execute()
        elif mode == "ALL":
            domain_input = inquirer.text(message="Enter Domain(s), comma-separated:").execute()
            keyword_input = inquirer.text(message="Enter Keyword(s), comma-separated (for Social Media Scan):").execute()
            start_date = inquirer.text(message="Start Date (YYYY-MM-DD):", validate=validate_date).execute()
            # Only ask once as per prompt
            end_date = inquirer.text(message="End Date (YYYY-MM-DD):", validate=validate_date).execute()
            
    # Execution
    if mode == "PS" or mode == "ALL":
        # Parse domains
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        for d in domains:
            run_phishing_scan(d, start_date, end_date)
        
    if mode == "SMS" or mode == "ALL":
        keywords = [k.strip() for k in keyword_input.split(",") if k.strip()]
        for k in keywords:
            run_social_media_scan(k, start_date, end_date)
        
    # Screenshots (Always run after scans?)
    take_screenshots_logic()
    
    print("\n[+] Operation Completed.")

if __name__ == "__main__":
    main()
