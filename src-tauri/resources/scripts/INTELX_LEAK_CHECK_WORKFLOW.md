# IntelX leak check — use this repo’s scripts (not `add_feed`)

**Master index of all script workflows:** `**SCRIPT_WORKFLOWS.md`** (IntelX is §6 there too).

When someone asks to **check an email, domain, or other target for leaks** using **Intelligence X** in this workspace, use the `**Intelx_Crawler`** project. Do **not** invent:

- `feed_search(source="misp", …)` for IntelX
- `add_feed` with `ftype: "intelx"` and a fake `https://intelx.example.com/api` — **that pattern is not defined in this repository** and is not how IntelX is integrated here.

This folder talks to the real API base `**https://2.intelx.io`** from code in `Intelx_Crawler/main.py`.

---

## 1. Where the code lives


| Item                               | Path                                         |
| ---------------------------------- | -------------------------------------------- |
| Project root                       | `All_Scripts/Intelx_Crawler/`                |
| Entry script                       | `Intelx_Crawler/main.py`                     |
| Launcher (from `All_Scripts` root) | `./run.sh Intelx_Crawler`                    |
| Launcher (from project dir)        | `cd Intelx_Crawler && ./scripts/venv_run.sh` |


Venv: `Intelx_Crawler/.venv` (created on first `run.sh` / `venv_run.sh`).

---

## 2. What the script does (workflow)

1. **Prompts** (interactive) for:
  - **Target(s)** — comma-separated. Valid types include **email**, **domain**, **IP**, **CIDR**, **URL** (see `validate_inputs` in `main.py`).
  - **Start and end date** — `YYYY-MM-DD` (search window for IntelX).
  - **Search limit** — default `2000` if you press Enter.
2. **POST** `https://2.intelx.io/intelligent/search` with the term, dates, and headers (API key).
3. **Fetches** search results, then **downloads** file previews / raw data per record.
4. **Writes** under `Intelx_Crawler/` (working directory when you run the script):
  - `csv_output/…` — per-run CSV output tree
  - `final_report/…` — combined reporting step (`pii_reporter`)
  - `filtered/…` — matched credential-style outputs when the pipeline finds hits

Analysts review **CSVs and reports on disk**; this repo does **not** auto-import into MISP/OpenCTI unless you add that integration.

---

## 3. How to run it (operator steps)

From the **All_Scripts** directory:

```bash
cd /path/to/All_Scripts
./run.sh Intelx_Crawler
```

When prompted for targets, enter one or more values, e.g. a **single email**:

```text
user@example.com
```

Then enter **start date**, **end date**, and **limit** as required.

**API key:** `main.py` currently sets `API_KEY` and `headers` at the top of the file. For production, move the key to an environment variable and read it in code—**never** commit real keys. Replace the placeholder with your **Intelligence X** API key from your account.

---

## 4. Mapping: old (wrong) vs correct


| Wrong (not in this repo)                                        | Correct here                                                                                                                    |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `feed_search(source="misp", value="…")` for an “IntelX” request | Use `**Intelx_Crawler`**; MISP is a different component (`shared_cti` / your TIP).                                              |
| `add_feed` + `ftype: "intelx"` + example URL                    | **No** `add_feed` in this repo. Use `**./run.sh Intelx_Crawler`** and `https://2.intelx.io` in **code** (already in `main.py`). |
| OpenCTI / OTX poller config blocks                              | **Not** shipped as YAML here; use **this script** or your platform’s **native** IntelX connector **outside** this tree.         |


---

## 5. Legal and policy

- Use only for **authorized** purposes (e.g. **your** org’s accounts, **approved** fraud/IR cases, **signed** client work).
- Respect **Intelligence X ToS** and data-handling policy.
- Do not use live **personal** examples in team documentation; use `**user@example.com`** in docs.

---

## 6. See also

- `CTI_TEAM_USAGE_AND_WORKFLOWS.md` — § IntelX / breach-ATO (governed use).
- `CTI_FUNCTION_MAP.md` — IntelX row in the function table.
- `README.txt` — generic `./run.sh` help.

For **MISP/VT/TAXII enrichment** of an indicator *after* you have it from another source, see `shared_cti/` — that is **separate** from the IntelX **search** pipeline in `Intelx_Crawler`.