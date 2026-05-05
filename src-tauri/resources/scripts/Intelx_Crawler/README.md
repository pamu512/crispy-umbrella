---

```markdown
# IntelX Crawler

This project automates IntelX queries and organizes leaked data into structured CSV reports with optional credential extraction.

---

## Prerequisites

### 1. Install Docker

Ensure that Docker Desktop is installed:  
https://www.docker.com/products/docker-desktop/  
(Supports macOS, Windows, and Linux)

---

### 2. Open Terminal and Navigate to the Project Folder

#### For macOS / Linux:

1. Open the Terminal application.
2. Navigate to the project directory:

```bash
cd ~/Desktop/intelx
```

If the project is located on your desktop, this path will work.
Alternatively, you can drag the folder into the terminal window to auto-fill the path.

---

#### For Windows (PowerShell):

1. Press `Win + R`, type `powershell`, and press Enter.
2. Navigate to the folder:

```powershell
cd "C:\Users\YourName\Desktop\intelx"
```

---

## One-Command Execution

Run the following command inside the `intelx` project folder:

```bash
docker compose run --rm -it intelx-scraper
```

It may take longer during the first run due to image building.

You will then see a prompt:

```
Enter a domain, URL, Email, IP, CIDR, address, and more... eg. domain1, domain2 :
```

Input targets such as:

```
blackwired.com, nru.gov.sa
```

Multiple domains should be separated with commas.

---

## Output Structure

The crawler automatically saves results into the following structure:


| Folder                                     | Description                                                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `intelx/csv_output/<target_folder>`        | Contains individual raw result CSV files                                                               |
| `intelx/original_raw_data/<target_folder>` | Contains original raw data without filter                                                              |
| `intelx/final_report/<target>.csv`         | Combined report with automatic PII detection                                                           |
| `intelx/filtered/<target>.csv`             | Filtered report containing leaked credentials,if no file exist, it means there's no leaked credentials |
| `intelx/Credential/<target>.csv`           | Extracted credentials only (domain, username/email, password)                                          |


Example for the input `blackwired.com`:

- `intelx/csv_output/blackwired_com/`
Contains all raw files that include the target domain or keyword.
- `intelx/final_report/blackwired_com.csv`
A combined file summarizing all results contained in the csv_output folder.
- `intelx/filtered/blackwired_com.csv`
Contains only records that include leaked credentials.
- `intelx/Credential/blackwired_com.csv`
Contains only extracted domain, username/email, and password.

---

## Notes

- Ensure you are inside the project folder when executing:

```bash
docker compose run --rm -it intelx-scraper
```

- All output files are stored within `csv_output/`, `final_report/`, `filtered/`, and `Credential/`.
These files will remain on your machine until deleted manually.

---

## Summary

The only command you need to remember is:

```bash
docker compose run --rm -it intelx-scraper
```

