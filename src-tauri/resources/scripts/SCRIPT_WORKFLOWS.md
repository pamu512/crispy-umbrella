# Explicit workflows for all scripts (All_Scripts)

This is the **master runbook** for every application in the workspace. **IntelX** also has a focused copy: `**INTELX_LEAK_CHECK_WORKFLOW.md`** (same essential steps, extra anti-patterns for assistants).

**Conventions**

- **Root** = directory that contains all project folders (e.g. `All_Scripts/`).
- **Do not** invent `add_feed`, `ftype: …`, or generic TIP APIs—this repo uses **project code** and **env** per below.
- **Tor**-using scripts: use only where **legal and authorized**; isolate **network** as your policy requires.

---

## Table of contents

1. [Launcher only: `run.sh` / `scripts/venv_run.sh](#1-launcher-only-runsh--scriptsvenv_runsh)`
2. [ASM-fetch-main (attack surface / eASM)](#2-asm-fetch-main-attack-surface--easm)
3. [CVE_Project_NVD (NVD, KEV, OT, CVE search)](#3-cve_project_nvd-nvd-kev-ot-cve-search)
4. [Compromised_user_Mac (Tor .onion marketplace logs)](#4-compromised_user_mac-tor-onion-marketplace-logs)
5. [IOCs-crawler-main (threat news / blog scrapers)](#5-iocs-crawler-main-threat-news--blog-scrapers)
6. [Intelx_Crawler (Intelligence X API)](#6-intelx_crawler-intelligence-x-api)
7. [Phishing_and_Social_Media_All-in-one (Brand Scout)](#7-phishing_and_social_media_all-in-one-brand-scout)
8. [Ransomware_live_event_victim (Ransomware.live PRO)](#8-ransomware_live_event_victim-ransomwarelive-pro)
9. [Social_MediaV2 (Tor + search + screenshots)](#9-social_mediav2-tor--search--screenshots)
10. [shared_cti (MISP / VT / TAXII sketches)](#10-shared_cti-misp--vt--taxii-sketches)

---

## 1. Launcher only: `run.sh` / `scripts/venv_run.sh`


| Item                | Path                            |
| ------------------- | ------------------------------- |
| Root launcher       | `All_Scripts/run.sh`            |
| Per-project wrapper | `<Project>/scripts/venv_run.sh` |
| Venv                | `<Project>/.venv`               |


**Workflow**

1. From **root**: `./run.sh <ProjectFolder>` — creates `<Project>/.venv` if missing, `pip install -r requirements.txt`, runs `main.py` (or an alternate `.py` you pass).
2. From **inside** a project: `./scripts/venv_run.sh` — same, without typing the project name.
3. **Not** intel by itself: it only **starts** the right Python app.

**Wrong:** treating `run.sh` as a MISP/OTX/IntelX **connector**; it is only a **Python runner**.

---

## 2. ASM-fetch-main (attack surface / eASM)

**Purpose:** External attack-surface **discovery** (subdomains, services, Shodan / SecurityTrails / FOFA as configured in code), **API** for scans and **exports**—see project `README.md`.


| Item                   | Path                                                                               |
| ---------------------- | ---------------------------------------------------------------------------------- |
| Project root           | `All_Scripts/ASM-fetch-main/`                                                      |
| App entry (API)        | `main.py`                                                                          |
| Heavy integration code | `ASM-fetch-main/src/` (e.g. `api/shodan.py`, `api/fofa.py`, `tasks/scan_tasks.py`) |


**Intended production workflow: Docker (recommended in README)**

1. Install **Docker** + **Docker Compose**.
2. `cd ASM-fetch-main`
3. Configure `.env` (DB, Redis, **API keys** for Shodan, SecurityTrails, FOFA, etc. per your deployment).
4. `docker compose up --build`
5. Open **[http://localhost:8000/docs](http://localhost:8000/docs)** (FastAPI) to **create scans** and read **results/exports** as implemented by the routers.
6. `docker compose down --volumes --remove-orphans` when done (destroys anonymous volumes—see project README for nuance).

**Local Python (optional, for dev)**

- `./run.sh ASM-fetch-main` from **root** — runs `main.py` only; **Celery workers, Redis, DB** are usually expected by the design—**prefer Docker** for a full stack.

**Wrong:** Expecting a single `main.py` run to replace the **entire** stack without **Redis/Postgres/Celery** where the code depends on them.

**Outputs:** Database + HTTP API; **export** endpoints per implementation—not automatic MISP push.

---

## 3. CVE_Project_NVD (NVD, KEV, OT, CVE search)

**Purpose:** **Download/update** NVD- and related **feeds**, **search** CVEs in a **date** range, **filter** by vendor and **CVSS** thresholds, **combine** NVD + CVE Project + **OT** data, **verify** dates, **exploit/POC** pass—see `main.py` and `output_result/`.


| Item         | Path                           |
| ------------ | ------------------------------ |
| Project root | `All_Scripts/CVE_Project_NVD/` |
| Entry        | `main.py`                      |


**Workflow (interactive)**

1. From **root**: `./run.sh CVE_Project_NVD` (or `cd CVE_Project_NVD && ./scripts/venv_run.sh`).
2. When prompted, choose:
  - `update` — **Update** NVD + related project feeds (can take time / bandwidth).  
  - `download` — **Download** NVD + CVEProject feeds.  
  - `search` — **Search** CVEs: you will be asked:  
    - `start` and `end` **date** `YYYY-MM-DD`  
    - **Vendor** / source filter (comma-separated) or **blank** for all  
    - **CVSS v3** and **v4** thresholds, e.g. `>7.0` or blank
3. Search pipeline writes under `**output_result/`** and runs combine/filter/verify/POC steps per `Search()` in `main.py`.
4. **Tor** may be required for some fetch paths in your **environment** (see project README for behavior).

**Wrong:** Using MISP or IntelX **search** to replace this—those are different systems.

---

## 4. Compromised_user_Mac (Tor .onion marketplace logs)

**Purpose:** **Tor** HTTP to a `**.onion`** “logs” marketplace, with a **session Cookie**, filter by **domain** strings, **CSV** to `logs/`. **High governance** (legal, policy, ethics).


| Item            | Path                                                                                |
| --------------- | ----------------------------------------------------------------------------------- |
| Project root    | `All_Scripts/Compromised_user_Mac/`                                                 |
| Entry           | `main.py`                                                                           |
| Onion (in code) | `rumarkstror5mvg…onion` — can **change** if the site/URL model changes in `main.py` |


**Prerequisites:** **Tor** service the library can use (e.g. `RequestsTor` to **localhost:9050** or as configured in `main.py`).

**Workflow**

1. **Start Tor** (system or Tor Browser proxy per your `RequestsTor` setup).
2. `./run.sh Compromised_user_Mac`.
3. **Paste a valid `Cookie`** when prompted (site may require a logged-in session).
4. **Domains** comma-separated (e.g. `example.com,other.org`).
5. Script fetches the **onion** URL built in `get_rumark_log`, parses the **table**, and saves `**logs/<name>_logs.csv`**.

**Wrong:** Running without **policy approval**; **scraping** clearnet instead of the script’s **onion** target without code changes; assuming the cookie never **expires** (re-run with new cookie when 403/empty).

---

## 5. IOCs-crawler-main (threat news / blog scrapers)

**Purpose:** **Celery**-driven **scrapers** of **security news / blogs** into **RethinkDB** (`news` + `BW_crawler` in reference setup). `news_job.py` selects which **source module** to run (e.g. `elastic_security_labs` in the current default).


| Item                | Path                             |
| ------------------- | -------------------------------- |
| Project root        | `All_Scripts/IOCs-crawler-main/` |
| Celery / news entry | `news_job.py`                    |
| Scraper modules     | `IOCs-crawler-main/news/*.py`    |


**Workflow (simplified: full stack is deployment-specific)**

1. **Dependencies:** **Python**, **RethinkDB**, **Redis**, **Celery** workers and beat (see `celery_*.sh`, `docker_setup.sh` for Ubuntu-style setup — paths in those scripts may reference a **distribute-crawler** layout; adjust to **this** repo path on your host).
2. Start **RethinkDB**; create **DB** `BW_crawler` and **table** `news` if not present.
3. Start **Redis**.
4. **Install:** `pip install -r requirements.txt` in a venv (e.g. `./run.sh` pattern from project venv in `All_Scripts` style).
5. **Celery worker** + **beat** (or run `news_job` inline for a **one-shot** as your code allows—today `news_job.py` does `getElastic_security_labs.delay()` + print: **production** is Celery + worker).
6. **CTI** reads **RethinkDB** or exports; **not** a built-in MISP exporter.

**Wrong:** Expecting `./run.sh IOCs-crawler-main` alone to be a “complete” 24/7 **feed** with **no** DB/Redis—this project expects **infrastructure** behind it.

---

## 6. Intelx_Crawler (Intelligence X API)

**Purpose:** **Leak/breach**-style **search** and **file** retrieval from **[https://2.intelx.io](https://2.intelx.io)**, PII/credential **pipelines** in-repo.


| Item    | Path                          |
| ------- | ----------------------------- |
| Project | `All_Scripts/Intelx_Crawler/` |
| Entry   | `main.py`                     |


**Workflow (short; details + assistant rules)**

1. `./run.sh Intelx_Crawler`
2. Enter **target(s)**, **dates**, **limit**; ensure **API key** in `main.py` (or refactored to **env**).
3. Outputs: `csv_output/`, `final_report/`, `filtered/`.

**Full spec:** `**INTELX_LEAK_CHECK_WORKFLOW.md`**.

**Wrong:** `add_feed(ftype: intelx, …)` — **not** in this repository.

---

## 7. Phishing_and_Social_Media_All-in-one (Brand Scout)

**Purpose:** **Phishing** permutation + **DNS/WHOIS**, **social** **keyword** search, **screenshots** — **Docker**-centric in README.


| Item         | Path                                                |
| ------------ | --------------------------------------------------- |
| Project      | `All_Scripts/Phishing_and_Social_Media_All-in-one/` |
| Core example | `brand_scout.py`, `entrypoint.sh`                   |


**Workflow (per project README: Docker recommended)**

1. `cd Phishing_and_Social_Media_All-in-one`
2. `docker build -t br0k3nm1rr0r/brand-scout .` (or the image name you use).
3. **Interactive:** `docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout` then choose **PS** / **SMS** / **ALL** and follow prompts (domains, keywords, **dates**).
4. **Output** to `/workdir` on the container (your bind-mounted project dir) as images + structured results per the tool.

**Python / venv (no top-level `main.py` in this folder):** use `**brand_scout.py`** or the path you need:

```bash
./run.sh Phishing_and_Social_Media_All-in-one brand_scout.py
```

There is also `**social_media/main.py**` for SMS-oriented flows inside the tree. Prefer **Docker** when the README requires **privileged** or Docker-in-Docker.

**Wrong:** Assuming a single **IntelX-style** `main.py` at the project root covers all features—this repo uses **brand_scout** + **Docker** as the main operator paths.

---

## 8. Ransomware_live_event_victim (Ransomware.live PRO)

**Purpose:** Export **victims** and **cyberattack/press** **CSVs** from the **Ransomware.live PRO** API for a **date range** (per-year source files are combined and filtered).


| Item    | Path                                                 |
| ------- | ---------------------------------------------------- |
| Project | `All_Scripts/Ransomware_live_event_victim/`          |
| Entry   | `main.py`                                            |
| API key | `**.env`**: `MY_API_KEY=…` (see project `README.md`) |


**Workflow (local Python)**

1. Set `**MY_API_KEY`** in `**.env`** in the project root.
2. From **All_Scripts** root: `./run.sh Ransomware_live_event_victim`.
3. Enter **start** and **end** date `YYYY-MM-DD` when prompted.
4. Script fetches per-year `output/victims/victims_<year>.csv` and `output/cyberattacks/cyberattacks_<year>.csv`, then writes filtered:
  - `output/victims_<start>_to_<end>.csv`  
  - `output/cyberattacks_<start>_to_<end>.csv`
5. **Country** names are normalized via `transform_country_full`.

**Workflow (Docker—per project README):** `docker compose run --rm -it app` and enter the same **date** prompts if that is your deployment.

**Wrong:** Confusing with **IntelX** or **MISP**; using the site **without** a valid **PRO** key.

---

## 9. Social_MediaV2 (Tor + search + screenshots)

**Purpose:** **Tor**-proxied **search**, **social**-style **results** to **CSV**, **Playwright** **screenshots**.


| Item        | Path                                                          |
| ----------- | ------------------------------------------------------------- |
| Project     | `All_Scripts/Social_MediaV2/`                                 |
| Docker      | `docker-run.sh`, `docker-compose` per repo                    |
| Local entry | `main.py` (for `./run.sh Social_MediaV2` when venv is enough) |


**Workflow (Docker—recommended in README)**

1. `cd Social_MediaV2`
2. `./docker-run.sh <target_name> [output_path] [num] [start_time] [end_time]`
3. Example: `./docker-run.sh "Acme Corp" ./output 10 2023-01-01 2023-12-31`
4. **Outputs** appear under the host path you pass as `output_path`.

**Workflow (local):** `./run.sh Social_MediaV2` runs `**main.py`**; you must have **Tor**, **Playwright** deps, and any **search** config the code expects—**Docker** matches the **tested** path.

**Wrong:** Treating output as a **MISP** feed; it is **OSINT / brand** **evidence** **collection**.

---

## 10. `shared_cti` (MISP / VT / TAXII sketches)

**Purpose:** **Enrichment**—`misp_search_attributes`, `virustotal_file_report`, `taxii_get_objects`—via **env** in `config.py`. **Not** a **feed** **registry** or `add_feed` **YAML** in this repo.


| Item    | Path                                                                             |
| ------- | -------------------------------------------------------------------------------- |
| Package | `All_Scripts/shared_cti/`                                                        |
| Deps    | `shared_cti/requirements-optional.txt` (and `taxii2-client` + `stix2` for TAXII) |


**Workflow**

1. `export VT_API_KEY=…` and/or `MISP_URL` + `MISP_KEY` and/or `TAXII`_* (see `shared_cti/config.py`).
2. `cd` to **All_Scripts**; `PYTHONPATH=.` `python3 -c "from shared_cti import virustotal_file_report; print('ok')"` (install `**requests`** first).
3. Call functions from **notebooks**, **Celery**, or **CLIs** you add—**no** long-running **poller** is started by this package alone.

**Wrong:** Expecting **OTX** / **OpenCTI** **connector** **blocks** here; use your **platform’s** **native** connectors or **extend** this code.

---

## Related files


| File                              | Content                                                                     |
| --------------------------------- | --------------------------------------------------------------------------- |
| `INTELX_LEAK_CHECK_WORKFLOW.md`   | IntelX **only**; assistant **anti-patterns** (`add_feed`, MISP for IntelX). |
| `CTI_FUNCTION_MAP.md`             | **CTI function** map per project.                                           |
| `CTI_TEAM_USAGE_AND_WORKFLOWS.md` | **Team** roles, governance, **Mermaid** **CTI** diagrams.                   |
| `AGENTS.md`                       | Rules for **AI** assistants.                                                |
| `README.txt`                      | **Quick** **run** commands and **pointers**.                                |


