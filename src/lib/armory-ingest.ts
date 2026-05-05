import type { CtiProjectId } from "@/lib/cti-tools"
import { invoke } from "@tauri-apps/api/core"
import { handleSync } from "@/lib/ingestion-ipc"
import { formatInvokeError } from "@/lib/invoke-error"

/** User-facing detail when Armory queues the RSS IOC worker instead of the native news sidecar; `null` = rethrow. */
function iocArmoryFeedCrawlFallbackDetail(errMsg: string): string | null {
  const m = errMsg
  if (
    /Feature ['"]IOCs-crawler-main['"] not found/i.test(m) ||
    /IOCs-crawler-main.*not found/i.test(m) ||
    /copy All_Scripts project folders/i.test(m) ||
    /export_iocs_to_cti_vault\.py not found/i.test(m) ||
    /bundled script not found/i.test(m)
  ) {
    return "IOCs-crawler-main bundle not available — started built-in Elastic Security Labs / Unit42 RSS crawl into cti_vault (no All_Scripts copy required)."
  }
  if (
    /no bundled sidecar for/i.test(m) ||
    /open sidecar/i.test(m) ||
    /sidecar exited/i.test(m) ||
    /sidecar execution failed/i.test(m)
  ) {
    return "IOC news crawler sidecar missing or failed (e.g. run `npm run build:python` so `ioc-news-crawler` is built). Started built-in Elastic Security Labs / Unit42 RSS crawl into cti_vault instead."
  }
  return null
}

/** Tools whose play action is handled by the Rust host (canonical `cti_vault` via `vault_db::get_vault_path`). */
export const ARMORY_NATIVE_BACKEND_IDS: ReadonlySet<string> = new Set([
  "CVE_Project_NVD",
  "ASM-fetch-main",
  "Ransomware_live_event_victim",
  "IOCs-crawler-main",
])

export function armoryNativeNeedsWorkspace(id: CtiProjectId): boolean {
  /** EASM uses only vault + domain; CVE zip and IOC export need a workspace directory. */
  return id === "CVE_Project_NVD" || id === "IOCs-crawler-main"
}

function defaultRansomwareStart(): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - 90)
  return d.toISOString().slice(0, 10)
}

function defaultRansomwareEnd(): string {
  return new Date().toISOString().slice(0, 10)
}

/**
 * Run the host ingestion path for an Armory tool. Always pass `vaultDbAbsolutePath` so IPC logs
 * align with the same DB as `get_vault_stats` / `CTI_DB_PATH` during the command.
 */
/** EASM / `invoke_easm_scan` — domain from UI (never use `window.prompt` in Tauri). */
export async function runArmoryNativeAsmScan(opts: {
  domain: string
  vaultDbAbsolutePath: string
}): Promise<{ title: string; detail: string }> {
  const domain = opts.domain.trim()
  if (!domain) {
    throw new Error("Seed domain is required.")
  }
  const v = opts.vaultDbAbsolutePath.trim()
  const n = await handleSync({
    kind: "asm",
    payload: { domain, vaultDbAbsolutePath: v },
  })
  return {
    title: "ASM scan complete",
    detail: `Processed ${n} asset row(s) into the vault.`,
  }
}

/** Native ingest invoked from Armory without extra dialogs (ASM uses {@link runArmoryNativeAsmScan}). */
export type ArmoryNativeIngestToolId =
  | "CVE_Project_NVD"
  | "Ransomware_live_event_victim"
  | "IOCs-crawler-main"

export async function runArmoryNativeIngest(opts: {
  toolId: ArmoryNativeIngestToolId
  workspacePath: string | null
  vaultDbAbsolutePath: string
}): Promise<{ title: string; detail: string }> {
  const { toolId, workspacePath, vaultDbAbsolutePath } = opts
  const v = vaultDbAbsolutePath.trim()
  const ws = (workspacePath ?? "").trim()

  switch (toolId) {
    case "CVE_Project_NVD": {
      const r = await handleSync({
        kind: "cve",
        payload: { workspacePath: ws, feedUrl: null, vaultDbAbsolutePath: v },
      })
      return {
        title: "CVE / NVD sync complete",
        detail: `Upserted ${r.cveRowsUpserted} CVE row(s). ZIP: ${r.zipPath}`,
      }
    }
    case "Ransomware_live_event_victim": {
      const msg = await handleSync({
        kind: "ransomware",
        payload: {
          startDate: defaultRansomwareStart(),
          endDate: defaultRansomwareEnd(),
          vaultDbAbsolutePath: v,
        },
      })
      return { title: "Ransomware.live sync complete", detail: msg }
    }
    case "IOCs-crawler-main": {
      try {
        const n = await invoke<number>("ingest_iocs_vault", { workspacePath: ws })
        return {
          title: "IOC vault sync complete",
          detail: `Rethink export / refresh finished (${n} row(s) reported from the IOC ingestor).`,
        }
      } catch (e) {
        const msg = formatInvokeError(e)
        const detail = iocArmoryFeedCrawlFallbackDetail(msg)
        if (!detail) throw e
        await invoke("enqueue_ioc_crawler_task", {
          workspacePath: ws,
          kind: "elastic_security_labs",
        })
        return {
          title: "IOC feed crawl queued",
          detail,
        }
      }
    }
    default:
      throw new Error(`No native host action for ${String(toolId)}.`)
  }
}
