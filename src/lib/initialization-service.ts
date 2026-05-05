import { invoke } from "@tauri-apps/api/core"

export type CtiBootstrapResult = {
  writableRoot: string
  vaultDbPath: string
  scriptsRoot: string | null
  /** True when the app was launched with `--dino-mode` (Barney persona + purple accent tint). */
  dinoMode?: boolean
}

/** Ensures AppData `cti-app/` tree, `config.json`, and returns canonical paths. */
export async function ensureCtiWritableLayout(): Promise<CtiBootstrapResult> {
  return await invoke<CtiBootstrapResult>("cti_bootstrap")
}
