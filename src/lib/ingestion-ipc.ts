import { invoke } from "@tauri-apps/api/core"

/** Matches `CveNvdUpdateResult` from the host (`#[serde(rename_all = "camelCase")]`). */
export type CveNvdUpdateResult = {
  zipPath: string
  cveRowsUpserted: number
}

/** Canonical absolute vault path from the host (`vault_db::get_vault_path`); echoed for IPC debugging. */
export type VaultPathHint = {
  vaultDbAbsolutePath: string
}

/** Discriminated payloads — keys are camelCase to match Rust `#[serde(rename_all = "camelCase")]`. */
export type IngestionSyncRequest =
  | { kind: "mac"; payload: { cookie: string; domains: string } & Partial<VaultPathHint> }
  | {
      kind: "ransomware"
      payload: { startDate: string; endDate: string; apiKey?: string } & Partial<VaultPathHint>
    }
  | { kind: "asm"; payload: { domain: string } & Partial<VaultPathHint> }
  | {
      kind: "cve"
      payload: { workspacePath: string; feedUrl: string | null } & Partial<VaultPathHint>
    }

export function handleSync(
  req: Extract<IngestionSyncRequest, { kind: "mac" }>
): Promise<string>
export function handleSync(
  req: Extract<IngestionSyncRequest, { kind: "ransomware" }>
): Promise<string>
export function handleSync(req: Extract<IngestionSyncRequest, { kind: "asm" }>): Promise<number>
export function handleSync(
  req: Extract<IngestionSyncRequest, { kind: "cve" }>
): Promise<CveNvdUpdateResult>
/** Bundled `intelx_native_sync.py` via sidecar (`run_intelx`). */
export async function runIntelxSync(payload: {
  target: string
  startDate: string
  endDate: string
  limit: string
}): Promise<string> {
  return invoke<string>("run_intelx", { payload })
}

/** Bundled `CVE_Project_NVD/main.py` (`run_cve_sync`): download/update feeds or search → `cve_data`. */
export async function runCveSync(payload: {
  action: "download" | "update" | "search"
  startDate?: string
  endDate?: string
  vendor?: string
}): Promise<string> {
  return invoke<string>("run_cve_sync", { payload })
}

/** Bundled `Compromised_user_Mac/main.py` (`run_mac_stealer`). Cookie omitted → OS keychain `mac_stealer_rumark_cookie`. */
export async function runMacStealerNative(payload: {
  cookie?: string
  domains: string
}): Promise<string> {
  const domains = payload.domains.trim()
  const cookie = payload.cookie?.trim()
  return invoke<string>("run_mac_stealer", {
    payload: {
      domains,
      ...(cookie ? { cookie } : {}),
    },
  })
}

/** Bundled `Ransomware_live_event_victim/main.py` (`run_ransomware_sync`). apiKey omitted → keychain `ransomware_live`. */
export async function runRansomwareNative(payload: {
  apiKey?: string
  startDate: string
  endDate: string
}): Promise<string> {
  const apiKey = payload.apiKey?.trim()
  return invoke<string>("run_ransomware_sync", {
    payload: {
      startDate: payload.startDate.trim(),
      endDate: payload.endDate.trim(),
      ...(apiKey ? { apiKey } : {}),
    },
  })
}

export async function handleSync(
  req: IngestionSyncRequest
): Promise<string | number | CveNvdUpdateResult> {
  // Tauri maps each Rust fn parameter (except injected `AppHandle`) to a top-level key — use `payload`.
  switch (req.kind) {
    case "mac":
      return invoke<string>("run_mac_stealer", {
        payload: {
          domains: req.payload.domains,
          ...(req.payload.cookie?.trim() ? { cookie: req.payload.cookie.trim() } : {}),
        },
      })
    case "ransomware": {
      const apiKey = req.payload.apiKey?.trim()
      if (apiKey) {
        return invoke<string>("run_ransomware_sync", {
          payload: {
            apiKey,
            startDate: req.payload.startDate,
            endDate: req.payload.endDate,
          },
        })
      }
      return invoke<string>("invoke_ransomware_live_sync", { payload: req.payload })
    }
    case "asm":
      return invoke<number>("invoke_easm_scan", { payload: req.payload })
    case "cve":
      return invoke<CveNvdUpdateResult>("invoke_cve_nvd_update", { payload: req.payload })
  }
}
