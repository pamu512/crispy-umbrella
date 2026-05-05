# 1. Abstract

This project exports **Victims** and **Cyberattack/Press events** data from the **Ransomware.live PRO API** and saves the results as CSV files.  
It supports generating **yearly raw exports** and producing a **date-range filtered CSV** based on user-provided start/end dates.

---

# 2. Usage (Docker)

## 2.1 Change API key in `.env`

Find `.env` in the project root (see `.env.example`) and set your key:

```env
MY_API_KEY=YOUR_API_KEY_HERE
```

## 2.2 Run (interactive)

Run the program using Docker Compose:

```bash
docker compose run --rm -it app
```

Then enter:

- Start date: `YYYY-MM-DD` (e.g., `2025-01-01`)
- End date: `YYYY-MM-DD` (e.g., `2025-02-02`)

Notes:

- Use **zero-padded** format `YYYY-MM-DD` (e.g., `2025-03-01`, not `2025-3-1`)
- `--rm` removes the container automatically after it finishes (clean exit)

---

# 3. Output results

All CSV outputs are written under the `output/` directory.

## 3.1 Yearly raw exports

These files store raw data fetched by year:

- `output/victims/victims_<year>.csv`
- `output/cyberattacks/cyberattacks_<year>.csv`

Example:

- `output/victims/victims_2025.csv`
- `output/cyberattacks/cyberattacks_2025.csv`

## 3.2 Date-range filtered exports

These files merge and filter yearly CSVs within the specified date range:

- `output/victims_<start>_to_<end>.csv`
- `output/cyberattacks_<start>_to_<end>.csv`

Example (dates use underscores in the filename):

- `output/victims_2025_01_01_to_2025_02_02.csv`
- `output/cyberattacks_2025_01_01_to_2025_02_02.csv`

---

# 4. How data collection works (“ingest”)

There is no separate ingest daemon: `**main.py` is the pipeline.**

1. **API** — For each calendar year between your start and end year (inclusive), the script calls the PRO API and writes the **yearly** CSVs under `output/victims/` and `output/cyberattacks/`.
2. **Filter** — It reads those yearly files, keeps rows whose `date` or `discovered_date` falls in your **inclusive** `[start_date, end_date]` string range (`YYYY-MM-DD`), and writes the **filtered** CSVs at `output/` (paths in §3.2).
3. **Normalize** — `transform_country_full` rewrites country fields in the filtered victim and cyberattack CSVs.

Use the **filtered** `output/victims_…_to_….csv` (and cyberattacks twin) as your analyst-ready slices; keep the per-year files for re-filtering or auditing.

---

# 5. CTI Command Center (non-interactive)

When the app runs this project (no TTY), it sets `**CTI_NON_INTERACTIVE=1`**. Then:

- **Default date range:** **start of the current calendar year** (`YYYY-01-01`) through **today**. No prompts.
- **Overrides (optional):** set in the environment when launching the script:
  - `CTI_RW_START_DATE` — `YYYY-MM-DD`
  - `CTI_RW_END_DATE` — `YYYY-MM-DD`
- `**MY_API_KEY`** must be set (e.g. in `.env` in this project folder) or the run exits with an error before calling the API.

The Command Center **does not** automatically load these CSVs into `cti_vault.db`; it runs the exporter. If your workspace SQLite has a `Ransomware_live_event_victim` (or similar) table, load the filtered CSV using your own ETL or DBA workflow from the paths above.

---

# 6. Local Python

From this directory, with a venv and `pip install -r requirements.txt`:

```bash
python main.py
```

With a terminal, you will be prompted for start/end dates. With **no** TTY (or `CTI_NON_INTERACTIVE=1`), the same defaults and env vars as §5 apply.