"use client"

import * as React from "react"
import { invoke } from "@tauri-apps/api/core"

type CtiBootstrapPayload = {
  scriptsRoot?: string | null
}

/**
 * When the selected workspace is not the app writable root, {@link useWorkspace} omits `scriptsRoot`.
 * The host still knows the bundled `Resource/scripts` path — use it for `run_project_script` so
 * `Intelx_Crawler`, `Compromised_user_Mac`, etc. resolve without copying folders into the workspace.
 */
export function useBundledScriptsRoot(contextScriptsRoot: string | null | undefined): string | undefined {
  const [fallback, setFallback] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (contextScriptsRoot) return
    let cancelled = false
    void invoke<CtiBootstrapPayload>("cti_bootstrap")
      .then((b) => {
        const s = typeof b.scriptsRoot === "string" ? b.scriptsRoot.trim() : ""
        if (!cancelled && s) setFallback(s)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [contextScriptsRoot])

  return contextScriptsRoot ?? fallback ?? undefined
}
