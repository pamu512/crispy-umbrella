"use client"

import * as React from "react"
import { motion } from "framer-motion"
import { invoke } from "@tauri-apps/api/core"
import { useAppToast } from "@/components/app-toast"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { ARMORY_NATIVE_BACKEND_IDS, armoryNativeNeedsWorkspace, runArmoryNativeIngest } from "@/lib/armory-ingest"
import { CTI_TOOL_PROJECTS, type CtiProjectId } from "@/lib/cti-tools"
import { invokeRunProject } from "@/lib/run-project"
import { IntelxRunDialog } from "@/components/workspace/IntelxRunDialog"
import { SocialMediaRunDialog } from "@/components/workspace/SocialMediaRunDialog"
import { PhishingRunDialog } from "@/components/workspace/PhishingRunDialog"
import { CompromisedUserMacRunDialog } from "@/components/workspace/CompromisedUserMacRunDialog"
import { EasmNativeRunDialog } from "@/components/workspace/EasmNativeRunDialog"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"
import { formatInvokeError } from "@/lib/invoke-error"
import { fetchVaultStats } from "@/lib/vault-search"
import { useBundledScriptsRoot } from "@/lib/use-bundled-scripts-root"
import { ChevronLeft, ChevronRight, Loader2, Play } from "lucide-react"

interface ProjectStatus {
  name: string
  exists: boolean
}

/** Resolve via `Resource/scripts` + workspace cwd — validation may show no folder under workspacePath. */
const DIALOG_SCRIPT_ARMORY_IDS = new Set<string>([
  "Intelx_Crawler",
  "Social_MediaV2",
  "Phishing_and_Social_Media_All-in-one",
  "Compromised_user_Mac",
])

export function ProjectToolbox({
  collapsed,
  onCollapsedChange,
  onScriptActivity,
  /** `drawer` / `pillar` = full-width Armory (no rail collapse). */
  layoutVariant = "rail",
}: {
  collapsed: boolean
  onCollapsedChange: (v: boolean) => void
  onScriptActivity: () => void
  layoutVariant?: "rail" | "drawer" | "pillar"
}) {
  const { workspacePath, scriptsRoot } = useWorkspace()
  const effectiveScriptsRoot = useBundledScriptsRoot(scriptsRoot)
  const pushToast = useAppToast()
  const [vaultDbPath, setVaultDbPath] = React.useState<string | null>(null)
  const [statuses, setStatuses] = React.useState<Record<string, boolean>>({})
  const [venvReady, setVenvReady] = React.useState<Record<string, boolean>>({})
  const [settingUp, setSettingUp] = React.useState<Record<string, boolean>>({})
  const [running, setRunning] = React.useState<Record<string, boolean>>({})
  const [intelxOpen, setIntelxOpen] = React.useState(false)
  const [socialOpen, setSocialOpen] = React.useState(false)
  const [phishingOpen, setPhishingOpen] = React.useState(false)
  const [rumarkOpen, setRumarkOpen] = React.useState(false)
  const [asmNativeOpen, setAsmNativeOpen] = React.useState(false)

  React.useEffect(() => {
    let cancelled = false
    void fetchVaultStats()
      .then((s) => {
        if (!cancelled) setVaultDbPath(s.vaultDbAbsolutePath?.trim() ? s.vaultDbAbsolutePath.trim() : null)
      })
      .catch(() => {
        if (!cancelled) setVaultDbPath(null)
      })
    return () => {
      cancelled = true
    }
  }, [workspacePath])

  React.useEffect(() => {
    if (!workspacePath) return
    const req = scriptsRoot
      ? invoke<ProjectStatus[]>("validate_features_bundle")
      : invoke<ProjectStatus[]>("validate_workspace", { path: workspacePath })
    req
      .then((res) => {
        const sm: Record<string, boolean> = {}
        res.forEach((r) => {
          sm[r.name] = r.exists
        })
        setStatuses(sm)
      })
      .catch((err) => console.warn("[workspace]", formatInvokeError(err)))
  }, [workspacePath, scriptsRoot])

  React.useEffect(() => {
    if (!scriptsRoot) {
      setVenvReady({})
      return
    }
    let cancelled = false
    ;(async () => {
      const next: Record<string, boolean> = {}
      for (const p of CTI_TOOL_PROJECTS) {
        if (p.scriptType !== "python") continue
        try {
          const s = await invoke<{
            featureName: string
            scriptDirExists: boolean
            venvReady: boolean
            requirementsPresent: boolean
          }>("feature_status", { featureName: p.id })
          if (!cancelled) next[p.id] = s.venvReady
        } catch {
          if (!cancelled) next[p.id] = false
        }
      }
      if (!cancelled) setVenvReady(next)
    })()
    return () => {
      cancelled = true
    }
  }, [scriptsRoot, statuses])

  const initFeature = async (id: string) => {
    setSettingUp((s) => ({ ...s, [id]: true }))
    setRunError(null)
    try {
      await invoke<string>("bootstrap_feature_venv", { featureName: id })
      const s = await invoke<{ venvReady: boolean }>("feature_status", { featureName: id })
      setVenvReady((m) => ({ ...m, [id]: s.venvReady }))
      onScriptActivity()
    } catch (e) {
      setRunError({ id, message: formatInvokeError(e) })
    } finally {
      setSettingUp((s) => ({ ...s, [id]: false }))
    }
  }

  const [runError, setRunError] = React.useState<{ id: string; message: string } | null>(null)
  const runErrorTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  React.useEffect(() => {
    if (!runError) return
    if (runErrorTimer.current) clearTimeout(runErrorTimer.current)
    runErrorTimer.current = setTimeout(() => setRunError(null), 12_000)
    return () => {
      if (runErrorTimer.current) clearTimeout(runErrorTimer.current)
    }
  }, [runError])

  const runOne = async (name: string, type: string) => {
    const id = name as CtiProjectId
    if (name === "Intelx_Crawler") {
      if (!workspacePath?.trim()) {
        pushToast({
          variant: "error",
          title: "IntelX",
          message: "Select a workspace before running IntelX.",
        })
        return
      }
      setIntelxOpen(true)
      return
    }
    if (name === "Social_MediaV2") {
      if (!workspacePath?.trim()) {
        pushToast({ variant: "error", title: "Social V2", message: "Select a workspace first." })
        return
      }
      setSocialOpen(true)
      return
    }
    if (name === "Phishing_and_Social_Media_All-in-one") {
      if (!workspacePath?.trim()) {
        pushToast({ variant: "error", title: "Phishing+", message: "Select a workspace first." })
        return
      }
      setPhishingOpen(true)
      return
    }
    if (name === "Compromised_user_Mac") {
      if (!workspacePath?.trim()) {
        pushToast({ variant: "error", title: "Mac compromise", message: "Select a workspace first." })
        return
      }
      setRumarkOpen(true)
      return
    }

    if (name === "ASM-fetch-main") {
      const v = vaultDbPath?.trim()
      if (!v) {
        pushToast({
          variant: "error",
          title: "Vault path unavailable",
          message: "Could not read the canonical SQLite vault from the host (get_vault_stats).",
        })
        return
      }
      setAsmNativeOpen(true)
      return
    }

    if (
      ARMORY_NATIVE_BACKEND_IDS.has(name) &&
      (name === "CVE_Project_NVD" ||
        name === "Ransomware_live_event_victim" ||
        name === "IOCs-crawler-main")
    ) {
      const v = vaultDbPath?.trim()
      if (!v) {
        pushToast({
          variant: "error",
          title: "Vault path unavailable",
          message: "Could not read the canonical SQLite vault from the host (get_vault_stats).",
        })
        return
      }
      if (armoryNativeNeedsWorkspace(id) && !workspacePath?.trim()) {
        pushToast({
          variant: "error",
          title: "Workspace required",
          message: "CVE zip path and IOC export need a workspace folder on disk.",
        })
        return
      }
      setRunError(null)
      setRunning((r) => ({ ...r, [name]: true }))
      try {
        const { title, detail } = await runArmoryNativeIngest({
          toolId: name,
          workspacePath: workspacePath?.trim() ?? null,
          vaultDbAbsolutePath: v,
        })
        pushToast({ variant: "success", title, message: detail })
        onScriptActivity()
      } catch (e) {
        const message = formatInvokeError(e)
        pushToast({ variant: "error", title: `${name} failed`, message })
        setRunError({ id: name, message })
        if (process.env.NODE_ENV === "development") {
          console.warn(`[Armory native] ${name}:`, message)
        }
      } finally {
        setRunning((r) => ({ ...r, [name]: false }))
      }
      return
    }

    if (!workspacePath) return
    setRunError(null)
    setRunning((r) => ({ ...r, [name]: true }))
    try {
      await invokeRunProject(workspacePath, name, type, null, null, null, null, {
        scriptsRoot: effectiveScriptsRoot,
      })
      onScriptActivity()
      pushToast({
        variant: "success",
        title: `${name} finished`,
        message: "Script run completed — check the host log for details.",
      })
    } catch (e) {
      const message = formatInvokeError(e)
      setRunError({ id: name, message })
      pushToast({ variant: "error", title: `${name} failed`, message })
      if (process.env.NODE_ENV === "development") {
        console.warn(`[CTI script] ${name}:`, message)
      }
    } finally {
      setRunning((r) => ({ ...r, [name]: false }))
    }
  }

  const drawer = layoutVariant === "drawer" || layoutVariant === "pillar"
  const showCollapsed = drawer ? false : collapsed

  return (
    <motion.aside
      layout={!drawer}
      className={cn(
        "relative flex min-h-0 shrink-0 flex-col bg-black/20",
        drawer ? "h-full min-h-0 w-full border-0" : "border-r border-white/10"
      )}
      style={drawer ? { width: "100%" } : { width: collapsed ? 52 : 220 }}
      transition={{ type: "spring", stiffness: 420, damping: 38 }}
    >
      <div className="flex h-11 shrink-0 items-center border-b border-white/10 px-1.5">
        {!showCollapsed ? (
          <span className="pl-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            {drawer ? (layoutVariant === "pillar" ? "Armory" : "Tools · Armory") : "Tools"}
          </span>
        ) : null}
        {!drawer ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ml-auto size-8 shrink-0 text-muted-foreground"
            onClick={() => onCollapsedChange(!collapsed)}
          >
            {collapsed ? <ChevronRight className="size-4" /> : <ChevronLeft className="size-4" />}
          </Button>
        ) : null}
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-0.5 p-1.5">
          {CTI_TOOL_PROJECTS.map((p) => {
            const ok = statuses[p.id]
            const bundle = Boolean(scriptsRoot)
            const py = p.scriptType === "python"
            const venvOk = !bundle || !py || venvReady[p.id]
            const hostNative = ARMORY_NATIVE_BACKEND_IDS.has(p.id)
            const needSetup = !hostNative && bundle && py && ok && !venvOk
            const nativePlayable =
              hostNative &&
              !!vaultDbPath?.trim() &&
              (!armoryNativeNeedsWorkspace(p.id) || !!workspacePath?.trim())
            // Dialog-first tools (IntelX, Mac, Social V2, Phishing+) must not require a matching folder
            // under workspacePath: runs resolve via Resource/scripts when scriptsRoot is set. Requiring
            // validate_workspace "exists" left Play permanently disabled for typical CTI_Command-only homes.
            const scriptPlayable =
              !hostNative &&
              (p.id === "Intelx_Crawler" ||
              p.id === "Compromised_user_Mac" ||
              p.id === "Social_MediaV2" ||
              p.id === "Phishing_and_Social_Media_All-in-one"
                ? !!workspacePath?.trim() && !needSetup
                : !!ok && !needSetup)
            const playDisabled = running[p.id] || !(nativePlayable || scriptPlayable)
            const bundledScriptsReachable = Boolean(effectiveScriptsRoot?.trim())
            const statusDotOk =
              hostNative
                ? !!vaultDbPath?.trim()
                : ok === undefined
                  ? undefined
                  : DIALOG_SCRIPT_ARMORY_IDS.has(p.id)
                    ? Boolean(ok) || bundledScriptsReachable
                    : Boolean(ok)
            const statusDotTitle =
              hostNative
                ? vaultDbPath
                  ? "Host sync (canonical vault)"
                  : "Vault path not loaded"
                : ok === undefined
                  ? "Checking script paths…"
                  : DIALOG_SCRIPT_ARMORY_IDS.has(p.id)
                    ? Boolean(ok)
                      ? "Scripts folder present under workspace"
                      : bundledScriptsReachable
                        ? "Bundled scripts available (app Resources — workspace copy optional)"
                        : "Scripts not found under workspace or bundle"
                    : ok
                      ? "Scripts present"
                      : "Missing"
            return (
              <div
                key={p.id}
                className={cn(
                  "flex flex-col gap-1 rounded-lg px-2 py-1.5 hover:bg-white/5",
                  showCollapsed && "items-center px-0"
                )}
                title={`${p.label} — ${p.hint}\n${p.id}`}
              >
                <div className={cn("flex items-center gap-2", showCollapsed && "justify-center")}>
                  <span
                    className={cn(
                      "size-2 shrink-0 rounded-full",
                      statusDotOk === undefined
                        ? "bg-zinc-600"
                        : statusDotOk
                          ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"
                          : "bg-zinc-600"
                    )}
                    title={statusDotTitle}
                  />
                  {!showCollapsed ? (
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium leading-tight">{p.label}</p>
                      <p className="truncate font-mono text-[9px] text-muted-foreground">{p.id}</p>
                      {hostNative ? (
                        <p className="truncate text-[9px] text-sky-400/90">Tauri host · same vault as vitals</p>
                      ) : null}
                    </div>
                  ) : null}
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className={cn("size-7 shrink-0 text-cyan-400/90", showCollapsed && "size-8")}
                    disabled={playDisabled}
                    title={
                      running[p.id]
                        ? "Running…"
                        : needSetup
                          ? "Initialize venv first (Init below)"
                          : playDisabled
                            ? !workspacePath?.trim()
                              ? "Select a workspace in the header / Workspace menu"
                              : "Cannot run yet"
                            : `Run ${p.label}`
                    }
                    aria-busy={running[p.id]}
                    onClick={() => void runOne(p.id, p.scriptType)}
                  >
                    {running[p.id] ? (
                      <Loader2 className="size-3.5 animate-spin" aria-hidden />
                    ) : (
                      <Play className="size-3.5" aria-hidden />
                    )}
                  </Button>
                </div>
                {!showCollapsed && bundle && py ? (
                  <div className="flex items-center justify-between pl-4">
                    <span className={cn("text-[9px]", venvOk ? "text-emerald-400/90" : "text-amber-300/90")}>
                      {venvOk ? "venv: ready" : "venv: setup"}
                    </span>
                    {needSetup ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-6 px-2 text-[9px]"
                        disabled={settingUp[p.id]}
                        onClick={() => void initFeature(p.id)}
                      >
                        {settingUp[p.id] ? "…" : "Init"}
                      </Button>
                    ) : null}
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
      </ScrollArea>
      {runError ? (
        <div className="shrink-0 border-t border-red-500/25 bg-red-950/25 px-2 py-1.5">
          <p className="font-mono text-[9px] leading-snug text-red-200/95">
            <span className="font-semibold text-red-300">{runError.id}</span>{" "}
            <span className="text-red-100/90">{runError.message}</span>
          </p>
        </div>
      ) : null}
      <IntelxRunDialog
        open={intelxOpen}
        onOpenChange={setIntelxOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          onScriptActivity()
          setRunning((r) => ({ ...r, Intelx_Crawler: true }))
          setTimeout(() => setRunning((r) => ({ ...r, Intelx_Crawler: false })), 2000)
        }}
      />
      <SocialMediaRunDialog
        open={socialOpen}
        onOpenChange={setSocialOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          onScriptActivity()
          setRunning((r) => ({ ...r, Social_MediaV2: true }))
          setTimeout(() => setRunning((r) => ({ ...r, Social_MediaV2: false })), 2000)
        }}
      />
      <PhishingRunDialog
        open={phishingOpen}
        onOpenChange={setPhishingOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          onScriptActivity()
          setRunning((r) => ({ ...r, "Phishing_and_Social_Media_All-in-one": true }))
          setTimeout(
            () => setRunning((r) => ({ ...r, "Phishing_and_Social_Media_All-in-one": false })),
            2000
          )
        }}
      />
      <CompromisedUserMacRunDialog
        open={rumarkOpen}
        onOpenChange={setRumarkOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          onScriptActivity()
          setRunning((r) => ({ ...r, Compromised_user_Mac: true }))
          setTimeout(() => setRunning((r) => ({ ...r, Compromised_user_Mac: false })), 2000)
        }}
      />
      {vaultDbPath?.trim() ? (
        <EasmNativeRunDialog
          open={asmNativeOpen}
          onOpenChange={setAsmNativeOpen}
          vaultDbAbsolutePath={vaultDbPath.trim()}
          onBusyChange={(busy) => setRunning((r) => ({ ...r, "ASM-fetch-main": busy }))}
          onSuccess={(result) => {
            pushToast({ variant: "success", title: result.title, message: result.detail })
            onScriptActivity()
          }}
          onError={(message) => {
            pushToast({ variant: "error", title: "ASM-fetch-main failed", message })
            setRunError({ id: "ASM-fetch-main", message })
          }}
        />
      ) : null}
    </motion.aside>
  )
}
