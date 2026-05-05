## Social Screenshot (Playwright)

Batch-generate screenshots from URLs listed in CSV files. The tool supports **platform-specific cleanup** for Facebook / Instagram / LinkedIn / TikTok / Twitter (X), and falls back to a **generic** screenshotter for everything else.

## Requirements

- **Python**: 3.9+ (recommended 3.10+)
- **Playwright**: Chromium is used by default (installed via Playwright)

## Install

From the project root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r screenshots_script/requirements.txt
python -m playwright install chromium
```

## CSV format

- The CSV must include a **header row** (column names in the first line)
- The CSV **must** contain a column named **`url`** (case-sensitive: it must be exactly `url`)
- The file is read as **UTF-8**
- Other columns are allowed and ignored by the screenshotter (e.g. `title`, `abstract`, `date`)
- Row numbers in output filenames match the CSV file’s row numbers:
  - Row 1 is the header
  - The first data row is **row 2**, so the first screenshot is usually `2.png`

Example:

```csv
title,url,abstract,date
Some post,https://www.facebook.com/...,"...",2025-11-07 08:14:44
```

## Usage (library API)

This project is a small Python library exposed via `screenshots_script`.

### Process a folder of CSVs

```python
from screenshots_script import run_folder

# Process all .csv files inside the folder
output_root = run_folder("Jack", headless=True)
print("Saved to:", output_root)
```

What it does:

- Finds all `*.csv` files in `input_folder`
- Detects platform per CSV (see **Platform detection** below)
- Writes screenshots to:
  - `<input_folder>_output/<csv_stem>/<row_number>.png`

Example (from this repo):

- Input: `Jack/Global.csv`, `Jack/Jack.csv`
- Output root: `Jack_output/`
- Outputs:
  - `Jack_output/Global/2.png`, `Jack_output/Global/3.png`, ...
  - `Jack_output/Jack/2.png`, ...

### Process a single CSV (force a platform)

```python
from screenshots_script import run_csv

run_csv("twitter", "Jack/Jack.csv", "Jack_output", headless=True)
```

## Usage (included example script)

There is a simple example runner at `sample.py`:

```bash
python sample.py
```

## Platform detection

When calling `run_folder(...)`, the platform for each CSV is chosen by:

- **Filename** (case-insensitive):
  - `facebook`, `instagram`, `linkedin` (or `linkin`), `tiktok`, `twitter` (or `x.com`, `x_`)
- If the filename doesn’t match, it inspects the **first non-empty URL** in the CSV
- If it still can’t detect, it uses **`generic`**

You can also override detection for an entire folder:

```python
from screenshots_script import run_folder

run_folder("Jack", platform="facebook")  # forces all CSVs to use Facebook runner
```

## Notes / troubleshooting

- **Login walls / popups**: The platform-specific runners try to close common dialogs and remove some overlays, but pages can still change.
- **Debugging**: Set `headless=False` so you can watch the browser.
- **Timeouts**: Each navigation/screenshot has timeouts; very heavy pages may still fail and will be logged while the run continues.

## Project layout

- `screenshots_script/runner.py`: folder/CSV orchestration (`run_folder`, `run_csv`)
- `screenshots_script/platforms/`: per-platform screenshot logic
- `screenshots_script/utils.py`: CSV parsing, platform detection, helpers

