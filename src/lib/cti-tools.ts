/** Eight CTI projects under All_Scripts workspace (tool belt). */
export const CTI_TOOL_PROJECTS = [
  { id: "Intelx_Crawler", scriptType: "sh" as const, label: "IntelX", hint: "Leak search (Compose)" },
  { id: "CVE_Project_NVD", scriptType: "python" as const, label: "CVE / NVD", hint: "NVD ingest" },
  { id: "ASM-fetch-main", scriptType: "python" as const, label: "ASM", hint: "Asset surface" },
  { id: "Ransomware_live_event_victim", scriptType: "python" as const, label: "Ransomware", hint: "Victim telemetry" },
  { id: "Phishing_and_Social_Media_All-in-one", scriptType: "python" as const, label: "Phishing+", hint: "Social / phish" },
  { id: "Social_MediaV2", scriptType: "python" as const, label: "Social V2", hint: "Social crawl" },
  { id: "IOCs-crawler-main", scriptType: "python" as const, label: "IOCs", hint: "IOC harvest" },
  { id: "Compromised_user_Mac", scriptType: "python" as const, label: "Mac Compromise", hint: "macOS IOCs" },
] as const

export type CtiProjectId = (typeof CTI_TOOL_PROJECTS)[number]["id"]

export function buildIntelxComposePreview(
  query: string,
  opts?: { startDate?: string | null; endDate?: string | null; searchLimit?: string | null }
): string {
  const start = opts?.startDate?.trim() || "2000-01-01"
  const end = opts?.endDate?.trim() || "2099-12-31"
  const lim = opts?.searchLimit?.trim() || "2000"
  return [
    "docker compose run --rm -i -T intelx-scraper",
    "  (cwd: Intelx_Crawler/)",
    "",
    "stdin (4 lines, same as bacongris workflow_runner):",
    `  1) query  → ${query}`,
    `  2) start  → ${start}`,
    `  3) end    → ${end}`,
    `  4) limit  → ${lim}`,
  ].join("\n")
}

export function buildGenericRunPreview(projectName: string, scriptType: string): string {
  if (scriptType === "sh") return `sh run.sh  (cwd: ${projectName}/)`
  if (projectName === "ASM-fetch-main") {
    return [
      `export_asm_to_cti_vault.py → workspace cti_vault.asm_assets (Postgres must be reachable; see ASM README)`,
      `If the script is missing: main.py only loads FastAPI; use Docker compose + API scans first.`,
    ].join("\n")
  }
  if (projectName === "Phishing_and_Social_Media_All-in-one") {
    return [
      `Brand Scout: brand_scout.py from project root — CTI dialog sets PS / SMS / ALL, domains &/or keywords, dates (-ps / -sms / -all per README).`,
      `After a successful run the app prefills Investigation Chat with an analysis prompt; Docker images (domain-sift, etc.) must exist on the host.`,
    ].join("\n")
  }
  if (projectName === "Ransomware_live_event_victim") {
    return [
      `Ransomware.live PRO → yearly CSVs under output/victims/ & output/cyberattacks/, then filtered range CSVs in output/.`,
      `Non-interactive (CTI): default Jan 1 this year → today; MY_API_KEY in .env; optional CTI_RW_START_DATE / CTI_RW_END_DATE.`,
    ].join("\n")
  }
  if (projectName === "Social_MediaV2") {
    return [
      `CTI: dialog → main.py -v1 <target> -v2 <project>/output -n <num> [--start-time][--end-time] (same as README docker-run.sh).`,
      `Tor + Playwright in .venv; CSVs under output/<target>/; vault table social_media_results after a successful run.`,
    ].join("\n")
  }
  if (projectName === "IOCs-crawler-main") {
    return [
      `Entry: news_job.py (Celery → Redis; crawlers write RethinkDB BW_crawler.news).`,
      `After a successful run the app syncs RethinkDB → cti_vault.ioc_news via export_iocs_to_cti_vault.py, then backfills ioc_records; or invoke ingest_iocs_vault when workers have finished.`,
    ].join("\n")
  }
  if (projectName === "Compromised_user_Mac") {
    return [
      `Hub / toolbox: run dialog → domains + optional cookie (passed as RUMARK_*).`,
      `Or set RUMARK_DOMAINS / RUMARK_COOKIE in All_Scripts/.env or project .env; Tor required.`,
    ].join("\n")
  }
  return [
    `${projectName}/.venv/bin/python main.py  (used if .venv exists)`,
    `else: python3 main.py`,
    `Missing modules: cd ${projectName} && python3 -m venv .venv && .venv/bin/pip install requests`,
  ].join("\n")
}
