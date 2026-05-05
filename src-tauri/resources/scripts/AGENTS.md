# Agent instructions (All_Scripts)

Use this file so automated assistants **follow the real layout** of this repository instead of inventing generic TIP/feed APIs.

## IntelX / “check for leaks” (email, domain, IP, etc.)

- **Do:** Direct the user to run `**Intelx_Crawler`** from this repo:
  - From workspace root: `./run.sh Intelx_Crawler`
  - Or: `cd Intelx_Crawler && ./scripts/venv_run.sh`
- **Read:** `INTELX_LEAK_CHECK_WORKFLOW.md` for the full operator workflow and API base (`https://2.intelx.io`).

**Do not** respond with:

- `add_feed` + `ftype: "intelx"` and placeholder URLs — **not implemented** in this repo.
- `feed_search(source="misp", …)` when the user asked for **IntelX** — MISP and IntelX are different; for IntelX use `Intelx_Crawler` (or `shared_cti` only for separate MISP **enrichment** per its docs).

## Other CTI docs

- `**SCRIPT_WORKFLOWS.md`** — **explicit runbooks** for **every** project (launcher, ASM, CVE, Tor Mac, IOCs crawler, IntelX, Brand Scout, Ransomware.live, Social_MediaV2, `shared_cti`).
- `CTI_FUNCTION_MAP.md` — which project maps to which CTI function.
- `CTI_TEAM_USAGE_AND_WORKFLOWS.md` — team roles and Mermaid workflows.
- `INTELX_LEAK_CHECK_WORKFLOW.md` — IntelX-focused copy (also §6 of `SCRIPT_WORKFLOWS.md`).
- `README.txt` — how to run projects with `./run.sh`.

## Shared enrichment (optional)

- `shared_cti/` — env-based **MISP**, **VirusTotal**, **TAXII** **sketches**; not a feed poller registry.