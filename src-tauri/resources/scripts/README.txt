Bacongris CTI — All_Scripts workspace
====================================

CTI: function map, team usage, and workflows
  see CTI_FUNCTION_MAP.md
  see CTI_TEAM_USAGE_AND_WORKFLOWS.md
Explicit per-script runbooks (launcher, each project, shared_cti)
  see SCRIPT_WORKFLOWS.md
IntelX leak checks (use Intelx_Crawler — not add_feed / example APIs)
  see INTELX_LEAK_CHECK_WORKFLOW.md
  see AGENTS.md for assistant routing rules

Quick start (from this directory)
---------------------------------

  ./run.sh

  Shows the same help as:  ./run.sh --help

  Run a project (creates that project’s .venv and runs main.py):

  ./run.sh <ProjectFolder>

  Example:

  ./run.sh CVE_Project_NVD
  ./run.sh Intelx_Crawler

  Or open a project folder and use the short form:

  cd Intelx_Crawler
  ./scripts/venv_run.sh

Projects are the folders that contain a requirements.txt file. Each one keeps its
own virtual environment in <ProjectFolder>/.venv (safe to delete to reset).

Optional smoke test (no network, sample JSON; stdlib only)
-----------------------------------------------------------

  python3 scripts/bacongris_smoke_test.py

  (Each project’s scripts/ folder is a small link to this same file for convenience.)

This entire directory is allowlisted for the agent. You can change the workspace
location in Cursor Settings.

Projects at a glance (where data comes from)
--------------------------------------------

  ASM-fetch-main
    External attack-surface: Shodan, SecurityTrails, FOFA, plus SSL/DNS/whois helpers
    in code — recon and exposure, not STIX/MISP “feeds”.

  CVE_Project_NVD
    NVD, CISA KEV, and related CVE/OT data (Tor optional for fetches in your flow).

  Compromised_user_Mac
    Tor to a .onion marketplace “logs” site; session cookie + HTML scrape to CSV.

  IOCs-crawler-main
    Public threat-reporting sites and RSS/Atom (blogs), scraped into RethinkDB — not
    TAXII/MISP.

  Intelx_Crawler
    Intelligence X API (2.intelx.io): leak-style search and file preview, then CSV/PII steps.

  Phishing_and_Social_Media_All-in-one  (Brand Scout)
    Phishing permutations, WHOIS/DNS, and social/brand surfaces with screenshots (Docker).

  Ransomware_live_event_victim
    Ransomware.live PRO API: victims and cyber/press event exports (date-range CSVs).

  Social_MediaV2
    Tor-proxied “Google CSE” style search + social result CSV and Playwright screenshots
    (Docker).

Shared MISP / TAXII / VirusTotal sketch
--------------------------------------

  Folder: shared_cti/  (not wired into every app yet; import when you add enrichment.)

  Set env: VT_API_KEY, MISP_URL, MISP_KEY, optional TAXII_USER, TAXII_PASSWORD,
  TAXII_COLLECTION_HREF (TAXII collection URL; see your feed’s docs). Optional: TAXII_DISCOVERY_URL for future discovery helpers.

  From the All_Scripts root (or PYTHONPATH=.), run Python:

    from shared_cti import virustotal_file_report, misp_search_attributes, taxii_get_objects

  Optional deps: pip install -r shared_cti/requirements-optional.txt
  and for TAXII: pip install taxii2-client stix2
