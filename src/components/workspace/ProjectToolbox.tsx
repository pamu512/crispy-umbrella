"use client"

import * as React from "react"
import { motion } from "framer-motion"
import { invoke } from "@tauri-apps/api/core"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { CTI_TOOL_PROJECTS } from "@/lib/cti-tools"
import { invokeRunProject } from "@/lib/run-project"
import { IntelxRunDialog } from "@/components/workspace/IntelxRunDialog"
import { SocialMediaRunDialog } from "@/components/workspace/SocialMediaRunDialog"
import { PhishingRunDialog } from "@/components/workspace/PhishingRunDialog"
import { CompromisedUserMacRunDialog } from "@/components/workspace/CompromisedUserMacRunDialog"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"
import { formatInvokeError } from "@/lib/invoke-error"
import { ChevronLeft, ChevronRight, Play } from "lucide-react"

interface ProjectStatus {
  name: string
  exists: boolean
}

export function ProjectToolbox({
  collapsed,
  onCollapsedChange,
  onScriptActivity,
}: {
  collapsed: boolean
  onCollapsedChange: (v: boolean) => void
  onScriptActivity: () => void
}) {
  const { workspacePath, scriptsRoot } = useWorkspace()
  const [statuses, setStatuses] = React.useState<Record<string, boolean>>({})
  const [venvReady, setVenvReady] = React.useState<Record<string, boolean>>({})
  const [settingUp, setSettingUp] = React.useState<Record<string, boolean>>({})
  const [running, setRunning] = React.useState<Record<string, boolean>>({})
  const [intelxOpen, setIntelxOpen] = React.useState(false)
  const [socialOpen, setSocialOpen] = React.useState(false)
  const [phishingOpen, setPhishingOpen] = React.useState(false)
  const [rumarkOpen, setRumarkOpen] = React.useState(false)

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
    if (!workspacePath) return
    if (name === "Intelx_Crawler") {
      setIntelxOpen(true)
      return
    }
    if (name === "Social_MediaV2") {
      setSocialOpen(true)
      return
    }
    if (name === "Phishing_and_Social_Media_All-in-one") {
      setPhishingOpen(true)
      return
    }
    if (name === "Compromised_user_Mac") {
      setRumarkOpen(true)
      return
    }
    setRunError(null)
    setRunning((r) => ({ ...r, [name]: true }))
    try {
      await invokeRunProject(workspacePath, name, type, null, null, null, null, {
        scriptsRoot: scriptsRoot ?? undefined,
      })
      onScriptActivity()
    } catch (e) {
      const message = formatInvokeError(e)
      setRunError({ id: name, message })
      if (process.env.NODE_ENV === "development") {
        console.warn(`[CTI script] ${name}:`, message)
      }
    } finally {
      setTimeout(() => setRunning((r) => ({ ...r, [name]: false })), 2000)
    }
  }

  return (
    <motion.aside
      layout
      className="relative flex shrink-0 flex-col border-r border-white/10 bg-black/20"
      style={{ width: collapsed ? 52 : 220 }}
      transition={{ type: "spring", stiffness: 420, damping: 38 }}
    >
      <div className="flex h-11 items-center border-b border-white/10 px-1.5">
        {!collapsed ? (
          <span className="pl-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Tools
          </span>
        ) : null}
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="ml-auto size-8 shrink-0 text-muted-foreground"
          onClick={() => onCollapsedChange(!collapsed)}
        >
          {collapsed ? <ChevronRight className="size-4" /> : <ChevronLeft className="size-4" />}
        </Button>
      </div>
      <ScrollArea className="flex-1">
        <div className="space-y-0.5 p-1.5">
          {CTI_TOOL_PROJECTS.map((p) => {
            const ok = statuses[p.id]
            const bundle = Boolean(scriptsRoot)
            const py = p.scriptType === "python"
            const venvOk = !bundle || !py || venvReady[p.id]
            const needSetup = bundle && py && ok && !venvOk
            return (
              <div
                key={p.id}
                className={cn(
                  "flex flex-col gap-1 rounded-lg px-2 py-1.5 hover:bg-white/5",
                  collapsed && "items-center px-0"
                )}
                title={`${p.label} — ${p.hint}\n${p.id}`}
              >
                <div className={cn("flex items-center gap-2", collapsed && "justify-center")}>
                  <span
                    className={cn(
                      "size-2 shrink-0 rounded-full",
                      ok === undefined ? "bg-zinc-600" : ok ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : "bg-zinc-600"
                    )}
                    title={ok ? "Scripts present" : "Missing"}
                  />
                  {!collapsed ? (
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium leading-tight">{p.label}</p>
                      <p className="truncate font-mono text-[9px] text-muted-foreground">{p.id}</p>
                    </div>
                  ) : null}
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className={cn("size-7 shrink-0 text-cyan-400/90", collapsed && "size-8")}
                    disabled={!ok || running[p.id] || needSetup}
                    title={needSetup ? "Initialize venv first" : `Run ${p.id}`}
                    onClick={() => void runOne(p.id, p.scriptType)}
                  >
                    <Play className="size-3.5" />
                  </Button>
                </div>
                {!collapsed && bundle && py ? (
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
    </motion.aside>
  )
}
