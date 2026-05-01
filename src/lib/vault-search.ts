import { invoke } from "@tauri-apps/api/core"

export interface VaultSearchResult {
  source: string
  title: string
  details: string
}

export async function searchVault(
  workspacePath: string,
  rawQuery: string
): Promise<VaultSearchResult[]> {
  const q = rawQuery.trim()
  if (!q) return []
  const searchTerm = `%${q.replace(/%/g, "\\%")}%`
  const allResults: VaultSearchResult[] = []

  const cves = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT cve_id, metadata FROM cve_data WHERE cve_id LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  cves.forEach((r) =>
    allResults.push({
      source: "CVE",
      title: String(r.cve_id ?? ""),
      details: String(r.metadata ?? "No metadata"),
    })
  )

  const leaks = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT company, group_name FROM Ransomware_live_event_victim WHERE company LIKE '${searchTerm}' OR group_name LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  leaks.forEach((r) =>
    allResults.push({
      source: "Ransomware",
      title: String(r.company ?? ""),
      details: `Group: ${r.group_name ?? ""}`,
    })
  )

  const assets = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT asset_target, metadata FROM asm_assets WHERE asset_target LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  assets.forEach((r) =>
    allResults.push({
      source: "Asset",
      title: String(r.asset_target ?? ""),
      details: String(r.metadata ?? ""),
    })
  )

  const iocs = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT ioc_value, type FROM iocs WHERE ioc_value LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  iocs.forEach((r) =>
    allResults.push({
      source: "IOC",
      title: String(r.ioc_value ?? ""),
      details: `Type: ${r.type ?? ""}`,
    })
  )

  const iocRec = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT ioc_value, ioc_type, metadata FROM ioc_records WHERE ioc_value LIKE '${searchTerm}' OR ioc_type LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  iocRec.forEach((r) =>
    allResults.push({
      source: "IOC record",
      title: String(r.ioc_value ?? ""),
      details: `${String(r.ioc_type ?? "")} — ${String(r.metadata ?? "")}`,
    })
  )

  const iocNews = await invoke<Record<string, string>[]>("query_db", {
    workspacePath,
    query: `SELECT title, url, source FROM ioc_news WHERE title LIKE '${searchTerm}' OR url LIKE '${searchTerm}' OR source LIKE '${searchTerm}' OR content_preview LIKE '${searchTerm}' LIMIT 12`,
  }).catch(() => [])

  iocNews.forEach((r) =>
    allResults.push({
      source: "IOC news",
      title: String(r.title ?? r.url ?? ""),
      details: `${String(r.source ?? "")} — ${String(r.url ?? "")}`,
    })
  )

  return allResults
}
