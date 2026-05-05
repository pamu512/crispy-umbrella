import { invoke } from "@tauri-apps/api/core"

/** Emitted by the host after vault-affecting jobs (e.g. NVD CVE ingest). */
export const VAULT_UPDATED_EVENT = "vault-updated" as const

/** Emitted when native IntelX sync (`intelx_native_sync.py`) starts — Barney shows a proactive line. */
export const ARMORY_TOOL_STARTED_EVENT = "armory-tool-started" as const

/** Bundled Armory folder missing or IntelX launcher incomplete — Barney shows Hunter's Alert in center chat. */
export const ARMORY_TOOL_MISSING_RESOURCE_EVENT = "armory-tool-missing-resource" as const

export type VaultStats = {
  iocRecords: number
  assetCveMappingRows: number
  cveDataRows: number
  distinctAssetsWithCve: number
  vaultDbAbsolutePath: string
}

export async function fetchVaultStats(): Promise<VaultStats> {
  return invoke<VaultStats>("get_vault_stats")
}

/** Recent `cve_data` rows from the canonical vault (`get_recent_cves_for_pulse`). */
export async function fetchRecentCvesFromPulse(limit = 18): Promise<
  { cve_id: string; severity_score?: number | string | null; description?: string }[]
> {
  const rows = await invoke<
    { cveId: string; severityScore?: number | null; description: string }[]
  >("get_recent_cves_for_pulse", { limit })
  return rows.map((r) => ({
    cve_id: r.cveId,
    severity_score: r.severityScore ?? undefined,
    description: r.description,
  }))
}

/** Recent `ioc_records` from the canonical vault (`get_recent_iocs_for_pulse`). */
export async function fetchRecentIocsFromPulse(limit = 18): Promise<
  { ioc_value: string; ioc_type: string; last_seen?: string; source_project?: string }[]
> {
  const rows = await invoke<
    { iocValue: string; iocType: string; lastSeen?: string | null; sourceProject?: string | null }[]
  >("get_recent_iocs_for_pulse", { limit })
  return rows.map((r) => ({
    ioc_value: r.iocValue,
    ioc_type: r.iocType,
    last_seen: r.lastSeen ?? undefined,
    source_project: r.sourceProject ?? undefined,
  }))
}

/** Markdown block: top critical CVEs + recent IOCs for Barney (`get_barney_environmental_context`). */
export async function fetchBarneyEnvironmentalContext(): Promise<string> {
  return invoke<string>("get_barney_environmental_context")
}

/** Hunter alert line after vault ingest (`get_hunter_alert_notification`). */
export async function fetchHunterAlertNotification(eventPayload?: unknown): Promise<string> {
  return invoke<string>("get_hunter_alert_notification", { eventPayload: eventPayload ?? null })
}

export type SearchVaultEntity =
  | "iocRecords"
  | "iocNews"
  | "iocsLegacy"
  | "cveData"
  | "asmAssets"
  | "ransomwareVictims"

export type SearchVaultOrder = "recentFirst" | "oldestFirst"

/** Mirrors `vault_search::SearchParams` (camelCase for Tauri / serde). */
export interface SearchVaultParams {
  workspacePath: string
  entity: SearchVaultEntity
  textContains?: string
  iocType?: string
  threatActor?: string
  sourceProject?: string
  dateRange?: { start?: string; end?: string }
  cveIdPrefix?: string
  minCvss?: number
  maxCvss?: number
  limit?: number
  order?: SearchVaultOrder
}

export async function invokeSearchVault<T extends Record<string, unknown> = Record<string, unknown>>(
  params: SearchVaultParams
): Promise<T[]> {
  // Tauri 2: Rust `fn search_vault(filters: SearchParams)` expects the key `filters` (not a flat spread).
  return invoke<T[]>("search_vault", { filters: params } as Record<string, unknown>)
}

const VAULT_ENTITY_LIST = [
  "iocRecords",
  "iocNews",
  "iocsLegacy",
  "cveData",
  "asmAssets",
  "ransomwareVictims",
] as const satisfies readonly SearchVaultEntity[]

const VAULT_ENTITY_SET = new Set<string>(VAULT_ENTITY_LIST)

/** Parse Ollama / copilot tool args into `search_vault` and return JSON for the tool message. */
export async function runSearchVaultFromToolArgs(
  workspacePath: string,
  args: Record<string, unknown>
): Promise<string> {
  const entityRaw = String(args.entity ?? "").trim()
  if (!VAULT_ENTITY_SET.has(entityRaw)) {
    return JSON.stringify({
      error: `Invalid entity "${entityRaw}". Use one of: ${VAULT_ENTITY_LIST.join(", ")}`,
    })
  }
  const params: SearchVaultParams = {
    workspacePath,
    entity: entityRaw as SearchVaultEntity,
  }
  const optStr = (k: string) => {
    const v = args[k]
    if (v == null) return
    const s = String(v).trim()
    if (s) (params as unknown as Record<string, unknown>)[k] = s
  }
  optStr("textContains")
  optStr("iocType")
  optStr("threatActor")
  optStr("sourceProject")
  optStr("cveIdPrefix")
  const lo = args.minCvss
  if (lo != null && Number.isFinite(Number(lo))) params.minCvss = Number(lo)
  const hi = args.maxCvss
  if (hi != null && Number.isFinite(Number(hi))) params.maxCvss = Number(hi)
  const lim = args.limit
  if (lim != null && Number.isFinite(Number(lim))) {
    params.limit = Math.min(500, Math.max(1, Math.floor(Number(lim))))
  }
  const ord = args.order
  if (ord === "recentFirst" || ord === "oldestFirst") params.order = ord
  const dr = args.dateRange
  if (dr != null && typeof dr === "object" && !Array.isArray(dr)) {
    const o = dr as Record<string, unknown>
    const start = o.start != null ? String(o.start).trim() : ""
    const end = o.end != null ? String(o.end).trim() : ""
    if (start || end) params.dateRange = { ...(start ? { start } : {}), ...(end ? { end } : {}) }
  }
  try {
    const rows = await invokeSearchVault(params)
    return JSON.stringify(rows)
  } catch (e) {
    return JSON.stringify({ error: String(e) })
  }
}

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
  const allResults: VaultSearchResult[] = []

  const cves = await invokeSearchVault({ workspacePath, entity: "cveData", textContains: q, limit: 12 }).catch(
    () => [] as Record<string, unknown>[]
  )
  cves.forEach((r) =>
    allResults.push({
      source: "CVE",
      title: String(r.cve_id ?? ""),
      details: String(r.metadata ?? "No metadata"),
    })
  )

  const leaks = await invokeSearchVault({
    workspacePath,
    entity: "ransomwareVictims",
    textContains: q,
    limit: 12,
  }).catch(() => [] as Record<string, unknown>[])
  leaks.forEach((r) =>
    allResults.push({
      source: "Ransomware",
      title: String(r.company ?? ""),
      details: `Group: ${String(r.group_name ?? "")}`,
    })
  )

  const assets = await invokeSearchVault({ workspacePath, entity: "asmAssets", textContains: q, limit: 12 }).catch(
    () => [] as Record<string, unknown>[]
  )
  assets.forEach((r) =>
    allResults.push({
      source: "Asset",
      title: String(r.asset_target ?? ""),
      details: String(r.metadata ?? ""),
    })
  )

  const iocs = await invokeSearchVault({ workspacePath, entity: "iocsLegacy", textContains: q, limit: 12 }).catch(
    () => [] as Record<string, unknown>[]
  )
  iocs.forEach((r) =>
    allResults.push({
      source: "IOC",
      title: String(r.ioc_value ?? ""),
      details: `Type: ${String(r.type ?? "")}`,
    })
  )

  const iocRec = await invokeSearchVault({ workspacePath, entity: "iocRecords", textContains: q, limit: 12 }).catch(
    () => [] as Record<string, unknown>[]
  )
  iocRec.forEach((r) =>
    allResults.push({
      source: "IOC record",
      title: String(r.ioc_value ?? ""),
      details: `${String(r.ioc_type ?? "")} — ${String(r.metadata ?? "")}`,
    })
  )

  const iocNews = await invokeSearchVault({ workspacePath, entity: "iocNews", textContains: q, limit: 12 }).catch(
    () => [] as Record<string, unknown>[]
  )
  iocNews.forEach((r) =>
    allResults.push({
      source: "IOC news",
      title: String(r.title ?? r.url ?? ""),
      details: `${String(r.source ?? "")} — ${String(r.url ?? "")}`,
    })
  )

  return allResults
}

function cveDescriptionFromMetadata(metadata: unknown): string {
  if (metadata == null) return ""
  if (typeof metadata === "string") {
    try {
      const d = JSON.parse(metadata) as { description?: string }
      return typeof d.description === "string" ? d.description : ""
    } catch {
      return metadata.slice(0, 400)
    }
  }
  if (typeof metadata === "object" && metadata !== null && "description" in metadata) {
    return String((metadata as { description?: unknown }).description ?? "")
  }
  return ""
}

function iocPreviewFromMetadata(metadata: unknown): string {
  if (metadata == null) return ""
  const s = typeof metadata === "string" ? metadata : JSON.stringify(metadata)
  return s.slice(0, 220)
}

export async function fetchRecentCvesForFeed(
  workspacePath: string,
  limit: number
): Promise<{ cve_id: string; severity_score?: number | string | null; description?: string }[]> {
  const rows = await invokeSearchVault({
    workspacePath,
    entity: "cveData",
    limit,
    order: "recentFirst",
  }).catch(() => [] as Record<string, unknown>[])
  return rows.map((r) => ({
    cve_id: String(r.cve_id ?? ""),
    severity_score: r.severity_score as number | string | null | undefined,
    description: cveDescriptionFromMetadata(r.metadata),
  }))
}

export async function fetchRecentIocRecordsForFeed(
  workspacePath: string,
  limit: number
): Promise<{ ioc_value: string; ioc_type: string; last_seen?: string; preview?: string }[]> {
  const rows = await invokeSearchVault({
    workspacePath,
    entity: "iocRecords",
    limit,
    order: "recentFirst",
  }).catch((e) => {
    console.warn("[vault-search] search_vault iocRecords failed:", e)
    return [] as Record<string, unknown>[]
  })
  return rows.map((r) => ({
    ioc_value: String(r.ioc_value ?? ""),
    ioc_type: String(r.ioc_type ?? ""),
    last_seen: r.last_seen != null ? String(r.last_seen) : undefined,
    preview: iocPreviewFromMetadata(r.metadata),
  }))
}

export async function fetchRecentAsmForFeed(
  workspacePath: string,
  limit: number
): Promise<{ asset_target: string; asset_type?: string; last_scan_at?: string; status?: string }[]> {
  const rows = await invokeSearchVault({
    workspacePath,
    entity: "asmAssets",
    limit,
    order: "recentFirst",
  }).catch((e) => {
    console.warn("[vault-search] search_vault asmAssets failed:", e)
    return [] as Record<string, unknown>[]
  })
  return rows.map((r) => ({
    asset_target: String(r.asset_target ?? ""),
    asset_type: r.asset_type != null ? String(r.asset_type) : undefined,
    last_scan_at: r.last_scan_at != null ? String(r.last_scan_at) : undefined,
    status: r.status != null ? String(r.status) : undefined,
  }))
}
