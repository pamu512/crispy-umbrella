"""
SSL Labs API module for fetching TLS/SSL info using ssllabs-scan subprocess.
"""

import logging
import os
import json
import csv
import subprocess
import tempfile
import datetime
import threading
import importlib.util
import shutil
import time

logger = logging.getLogger(__name__)

# Ensure logger propagates to root logger to respect main.py's logging configuration
logger.propagate = True

# Monkey patch ssllabs-scan to fix progress argument type
try:
    import ssllabsscan
    ssllabs_path = os.path.join(os.path.dirname(ssllabsscan.__file__), "ssllabs_client.py")
    spec = importlib.util.spec_from_file_location("ssllabs_client", ssllabs_path)
    ssllabs_client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ssllabs_client)

    orig_init = ssllabs_client.SSLLabsClient.__init__

    def patched_init(self, email, check_progress_interval_secs):
        if isinstance(check_progress_interval_secs, str):
            check_progress_interval_secs = int(check_progress_interval_secs)
        orig_init(self, email, check_progress_interval_secs)

    ssllabs_client.SSLLabsClient.__init__ = patched_init
except ImportError:
    logger.error("ssllabs-scan package not found")
    raise

def get_tls_ssl_info(host: str, max_retries: int = 2, timeout_seconds: int = 20, verbose: bool = False) -> str:
    """
    Fetch TLS/SSL info for a host using ssllabs-scan subprocess, with retry logic and CSV output.
    All files are stored in a unique temporary folder per host and cleaned up after execution.
    Subprocess output, CSV generation, and cleanup logs are only shown when verbose=True.

    Args:
        host: Domain or subdomain to assess.
        max_retries: Maximum retries for scan attempts.
        timeout_seconds: Timeout for each scan attempt (used for subprocess timeout).
        verbose: Enable verbose logging for detailed output, including subprocess output.

    Returns:
        Formatted summary string or "N/A" on failure or empty results.
    """
    # Create unique tmp folder per host in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sanitized_host = host.replace(".", "_")  # Sanitize for dir name
    tmp_dir = os.path.join(script_dir, f"tmp_{sanitized_host}")
    os.makedirs(tmp_dir, exist_ok=True)
    if verbose:
        logger.info(f"Using unique tmp dir for {host}: {tmp_dir}")

    try:
        date_time = datetime.datetime.now().strftime("%Y%m%d")
        out_dir = os.path.join(tmp_dir, host, date_time)
        os.makedirs(out_dir, exist_ok=True)

        json_path = os.path.join(out_dir, f"{host}.json")
        summary_csv = os.path.join(out_dir, "summary.csv")
        summary_html = os.path.join(out_dir, "summary.html")

        # Create a temporary input file in the unique tmp_dir
        inp_file = tempfile.NamedTemporaryFile(delete=False, dir=tmp_dir)
        inp_file.write(host.encode())
        inp_file.close()

        # Create a blank styles.css to avoid errors
        styles_path = os.path.join(os.path.dirname(ssllabsscan.__file__), "styles.css")
        if not os.path.exists(styles_path):
            with open(styles_path, "w") as f:
                f.write("")

        def run_scan(run_count):
            cmd = [
                "ssllabs-scan", inp_file.name,
                "--email", "zhushihao72@nyut.org.tw",
                "--output", summary_html,
                "--summary", summary_csv,
                "--progress", "0"
            ]
            if verbose:
                logger.debug(f"Executing subprocess command for {host}: {' '.join(cmd)}")
            try:
                result = subprocess.run(
                    cmd,
                    check=True,
                    timeout=timeout_seconds,
                    capture_output=True,
                    text=True
                )
                if verbose:
                    logger.info(f"Subprocess stdout for {host}:\n{result.stdout if result.stdout else 'No stdout output'}")
                    logger.info(f"Subprocess stderr for {host}:\n{result.stderr if result.stderr else 'No stderr output'}")
                logger.info(f"Scan completed for {host}: {json_path}")
                return parse_results(host, date_time, json_path, out_dir)
            except subprocess.CalledProcessError as e:
                if verbose:
                    logger.info(f"Subprocess stdout for {host} (failed):\n{e.stdout if e.stdout else 'No stdout output'}")
                    logger.info(f"Subprocess stderr for {host} (failed):\n{e.stderr if e.stderr else 'No stderr output'}")
                if run_count > 0:
                    logger.warning(f"Scan failed for {host}, retrying... (attempt {max_retries - run_count + 1}/{max_retries})")
                    time.sleep(5)  # Reduced from 15 to 5 seconds
                    return run_scan(run_count - 1)
                else:
                    logger.error(f"Scan failed for {host} after {max_retries} attempts: {e}")
                    return "N/A"
            except subprocess.TimeoutExpired as e:
                if verbose:
                    logger.info(f"Subprocess stdout for {host} (timeout):\n{e.stdout if e.stdout else 'No stdout output'}")
                    logger.info(f"Subprocess stderr for {host} (timeout):\n{e.stderr if e.stderr else 'No stderr output'}")
                logger.error(f"Timeout ({timeout_seconds}s) for {host}")
                return "N/A"
            finally:
                os.unlink(inp_file.name)

        def parse_results(domain, date_time, json_path, base_dir):
            if not os.path.exists(json_path):
                logger.error(f"JSON file not found: {json_path}")
                return "N/A"

            with open(json_path, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                data = data[0]

            endpoints = data.get("endpoints", [])
            certs = data.get("certs", [])

            if not endpoints:
                logger.info(f"No endpoints data for {domain}")
                return "N/A"

            sigAlg = "N/A"
            keyAlg = "N/A"
            if certs:
                cert = certs[0]
                sigAlg = cert.get("sigAlg", "N/A")
                keyAlg = cert.get("keyAlg", "N/A")

            protocols = set()
            suites = set()
            grades = set()
            server_names = set()

            for ep in endpoints:
                ip = ep.get("ipAddress", "N/A")
                grade = ep.get("grade", "N/A")
                status = ep.get("statusMessage", "N/A")
                server_name = ep.get("serverName", "N/A")
                grades.add(grade)
                server_names.add(server_name)

                details = ep.get("details", {})
                if "protocols" in details:
                    for p in details["protocols"]:
                        protocols.add(f'{p["name"]} {p["version"]}')
                if "suites" in details:
                    for group in details["suites"]:
                        for s in group.get("list", []):
                            suites.add(s.get("name", "N/A"))

                csv_path = os.path.join(base_dir, f"{ip}.csv")
                with open(csv_path, "w", newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Field", "Value"])
                    writer.writerow(["ipAddress", ip])
                    writer.writerow(["grade", grade])
                    writer.writerow(["statusMessage", status])
                    writer.writerow(["serverName", server_name])
                    writer.writerow(["protocols", "; ".join(sorted(protocols))])
                    writer.writerow(["cipher_suites", "; ".join(sorted(suites))])
                    writer.writerow(["sigAlg", sigAlg])
                    writer.writerow(["keyAlg", keyAlg])
                if verbose:
                    logger.info(f"CSV output generated: {csv_path}")

            grade_str = "; ".join(sorted(grades)) if grades else "N/A"
            server_name_str = "; ".join(sorted(server_names)) if server_names else "N/A"
            protocols_str = "; ".join(sorted(protocols)) if protocols else "N/A"
            suites_str = "; ".join(sorted(suites)) if suites else "N/A"

            if (grade_str == "N/A" and server_name_str == "N/A" and protocols_str == "N/A" and
                suites_str == "N/A" and sigAlg == "N/A" and keyAlg == "N/A"):
                logger.info(f"All TLS/SSL fields are N/A for {domain}")
                return "N/A"

            summary = f"Grade: {grade_str}; Server Name: {server_name_str}; Protocols: {protocols_str}; Cipher Suites: {suites_str}; SigAlg: {sigAlg}; KeyAlg: {keyAlg}"
            logger.info(f"Successfully fetched TLS/SSL info for {domain}")
            return summary

        return run_scan(max_retries)
    finally:
        # Clean up the unique tmp folder
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
            if verbose:
                logger.info(f"Cleaned up unique temporary folder: {tmp_dir}")