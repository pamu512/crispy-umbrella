# CVE Project + NVD Data + OT Vulnerability Search Tools

## Environment

- **Python:** 3.11.0
- **Pip:** 25.3

---

## Installation

Install the required dependencies using:

```bash
pip install -r requirements.txt
```

---

## Execution

Make sure you have already run Tor proxy on 127.0.0.1:9050 on the local machine:

Run the main script:

```bash
python main.py
```

Example:

```bash
CVE_Project_NVD % python main.py               
Press Enter 'update' to updating datas or 'search' to Search CVEs or 'download' to download CVEs data feeds: 
```

---

## Download

The first-time initialization requires running the `**download**` command to fetch local CVE databases.

### Example 1 — Download from NVD

```bash
Enter database type to download data feeds (e.g., 'nvd' or 'cve_project'): nvd
🔍 Fetching all JSON 2.0 feed links from NVD (keeping only .zip and .meta)...
Found 52 feed：
 - https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta
 - https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip
 - https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.meta
 - https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip
 ...
nvdcve-2.0-2003.meta Already exists, skipping download.
Downloading: nvdcve-2.0-2003.json.zip
📂 Decompression nvdcve-2.0-2003.json → NVD_CVE/JSON/nvdcve-2.0-2003.json
Complete decompression: nvdcve-2.0-2003.json.zip
🗑️ Deleted ZIP: nvdcve-2.0-2003.json.zip
All done!
```

---

### Example 2 — Download from the CVE Project

```bash
CVE_Project_NVD % python3 main.py
Press Enter 'update' to updating datas or 'search' to Search CVEs or 'download' to download CVEs data feeds: download
download
Enter database type to download data feeds (e.g., 'nvd' or 'cve_project'): cve_project
Starting CVE Project download/update (ZIP mode) ...
Initializing: 100%|██████████████████████████████| 2/2 [00:02<00:00,  1.01s/sec]
New update detected: 0fc32e9a72 ... downloading full dataset.
Downloading CVE Project ZIP archive (anonymous mode)...
Downloading: 100%|███████████████████████████| 522M/522M [01:55<00:00, 4.50MB/s]
✅ Download completed. Extracting contents ...
✅ Extraction completed! Final location: /Users/xxxx/Desktop/CP_NVD_OT/CVE_Project_NVD/CVE_Project_CVE/cves

Update completed successfully!
📂 Final path: /Users/xxxx/Desktop/CP_NVD_OT/CVE_Project_NVD/CVE_Project_CVE/cves
```

---

## Update

Use the `**update**` command to synchronize your local CVE database.

> 💡 *If your local database is outdated by a long time, using `download` might be faster.*

Example:

```bash
CVE_Project_NVD % python3 main.py 
Press Enter 'update' to updating datas or 'search' to Search CVEs or 'download' to download CVEs data feeds: update
update
Updating NVD feeds...
[*] nvdcve-2.0-2021 is up-to-date.
[*] nvdcve-2.0-2022 is up-to-date.
[*] nvdcve-2.0-2023 is up-to-date.
[*] nvdcve-2.0-2024 is up-to-date.
[*] nvdcve-2.0-2025 is up-to-date.
[*] Updating nvdcve-2.0-modified...
[+] Updated NVD_CVE/JSON/nvdcve-2.0-modified.json
[*] Updating nvdcve-2.0-recent...
[+] Updated NVD_CVE/JSON/nvdcve-2.0-recent.json
[*] All feeds are up-to-date.

Updating CVE Project data...
Starting CVE Project download/update (ZIP mode) ...
Initializing: 100%|██████████████████████████████| 2/2 [00:02<00:00,  1.01s/sec]
The local dataset is already up-to-date. Skipping download.
No new updates. The dataset is current.
```

---

## 🔎 Search

Search for CVEs by specifying a **date range** and **vendor name** (optional).

Example:

```bash
CVE_Project_NVD % python3 main.py 
Press Enter 'update' to updating datas or 'search' to Search CVEs or 'download' to download CVEs data feeds: search
search
Enter start date (YYYY-MM-DD): 2025-01-05
Enter end date (YYYY-MM-DD): 2025-11-05
Enter target sources(Vendor) separated by commas (or leave blank for all):
...
694🔍 Processed CVE-2018-18564 ...
695🔍 Processed CVE-2018-18565 ...
✅ Found 699 disclosure items after filtering.
💾 Saved results to OT_cve_search_result.csv
=====================================================
Starting data read and merge process...
merged_cve_result.csv File Statistics:
   - Total lines (incl. header): 41175
   - Valid unique CVE records read: 41174
OT_cve_search_result.csv File Statistics:
   - Total lines (incl. header): 700
   - Valid unique CVE records read: 699
=====================================================
Data Merge Statistics:
   - Primary file (Merged) count: 41174 records
   - Secondary file (OT) count: 699 records
   - Overlapping records: 53 records
   - Total unique CVE records processed: 41820 records
=====================================================
✅ Merge complete! Final file Final_cve.csv successfully created.
   - Final output record count: 41820 records
```

---

## Output Files

The following CSV files are generated after running the **search** command:


| **File Name**               | **Description**                                           |
| --------------------------- | --------------------------------------------------------- |
| `NVD_cve_search_result.csv` | Search results from the **NVD** database.                 |
| `CP_cve_search_result.csv`  | Search results from the **CVE Project** database.         |
| `merged_cve_result.csv`     | Merged results from both NVD and CVE Project and OT CVEs. |
| `OT_cve_search_result.csv`  | OT vulnerability results from **Claroty’s feed**.         |
| `Exploited_POC_CVEs.csv`    | The Exploited POC.                                        |


---

## 🧾 Summary


| Command    | Purpose                                           |
| ---------- | ------------------------------------------------- |
| `download` | Download the CVE/NVD database for the first time. |
| `update`   | Refresh and check for the latest dataset updates. |
| `search`   | Query and merge CVEs from local databases.        |


