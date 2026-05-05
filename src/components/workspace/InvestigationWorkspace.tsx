"use client"

import * as React from "react"
import { listen } from "@tauri-apps/api/event"
import { invoke } from "@tauri-apps/api/core"

import type { DashboardMetrics } from "@/components/OperationsOverview"
import { BarneyAgent } from "@/components/BarneyAgent"
import { DataIngestionHub } from "@/components/DataIngestionHub"
import { CommandPalette } from "@/components/workspace/CommandPalette"
import { LiveContextPanel } from "@/components/workspace/LiveContextPanel"
import { SplitHostConsole } from "@/components/workspace/TerminalDrawer"
import { VitalsBar, VitalsPills } from "@/components/workspace/VitalsBar"
import { VaultSettingsOverlay } from "@/components/workspace/VaultSettingsOverlay"
import { useScriptConsole } from "@/components/workspace/ScriptConsoleProvider"
import { useTelemetryPulse } from "@/components/workspace/telemetry-pulse-context"
import { OllamaSettingsDialog } from "@/components/OllamaSettingsDialog"
import { useOllamaSettings } from "@/components/OllamaSettingsProvider"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { triageFromConsoleLine } from "@/lib/console-triage"
import {
  fetchHunterAlertNotification,
  fetchVaultStats,
  ARMORY_TOOL_MISSING_RESOURCE_EVENT,
  ARMORY_TOOL_STARTED_EVENT,
  VAULT_UPDATED_EVENT,
  type VaultStats,
} from "@/lib/vault-search"
import { cn } from "@/lib/utils"
import { ProjectToolbox } from "@/components/workspace/ProjectToolbox"

function buildHunterBriefing(payload: unknown, stats: VaultStats | null): string {
  let kind = "vault"
  let extra = ""
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>
    if (typeof p.kind === "string") kind = p.kind
    if (p.cveRowsUpserted != null) extra += `\n\n**CVE rows upserted:** \`${String(p.cveRowsUpserted)}\``
  }
  const table = stats
    ? [
        `| Metric | Count |`,
        `| --- | ---: |`,
        `| IOC records | ${stats.iocRecords} |`,
        `| CVE data rows | ${stats.cveDataRows} |`,
        `| Asset–CVE mappings | ${stats.assetCveMappingRows} |`,
        `| Distinct assets (CVE) | ${stats.distinctAssetsWithCve} |`,
      ].join("\n")
    : "*Vault stats unavailable — check the vitals bar or reopen the Data Lab.*"
  return (
    `## Hunter's briefing\n\n` +
    `**Armory / vault signal:** \`${kind}\`${extra}\n\n` +
    `### Vault snapshot\n\n` +
    table +
    `\n\n**Suggested follow-ups:** chase lateral movement (CVE ↔ ASM ↔ creds), pressure-test exploitation likelihood, and hit IntelX / correlation from the Data Lab if the stack smells exposed.`
  )
}

const PILLAR_BOX =
  "flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-white/10 bg-[oklch(0.085_0.01_260)] shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]"

/**
 * Large-screen flex sizing for each pillar (`flex: grow shrink basis`).
 * Adjust these classes to change relative width; `min-w-*` / `max-w-*` clamp the workspace.
 */
const PILLAR_FLEX_LEFT =
  "lg:flex-[1_1_0%] lg:min-w-[min(100%,16rem)] lg:max-w-[min(100%,26rem)] xl:max-w-[min(100%,28rem)]"
const PILLAR_FLEX_CENTER =
  "lg:flex-[1.35_1_0%] lg:min-w-[min(100%,18rem)] xl:min-w-[20rem]"
const PILLAR_FLEX_RIGHT =
  "lg:flex-[1_1_0%] lg:min-w-[min(100%,14rem)] lg:max-w-[min(100%,24rem)] xl:max-w-[min(100%,26rem)]"

/**
 * Three-column dashboard: **Ingestion hub** · **Barney + host console** · **live alerts**.
 */
export function InvestigationWorkspace() {
  const { workspacePath, selectWorkspace } = useWorkspace()
  const { model, baseUrl } = useOllamaSettings()
  const { pulseToken, bumpTelemetry } = useTelemetryPulse()
  const { lines } = useScriptConsole()
  const [settingsOpen, setSettingsOpen] = React.useState(false)
  const [isVaultSettingsOpen, setIsVaultSettingsOpen] = React.useState(false)
  const [paletteOpen, setPaletteOpen] = React.useState(false)
  const armoryAnchorRef = React.useRef<HTMLDivElement>(null)
  const hostConsoleRef = React.useRef<HTMLDivElement>(null)
  const consoleTriageFired = React.useRef<Set<string>>(new Set())

  const [vaultStats, setVaultStats] = React.useState<VaultStats | null>(null)
  const [vaultLoading, setVaultLoading] = React.useState(false)
  const [vectorMetrics, setVectorMetrics] = React.useState<DashboardMetrics | null>(null)
  const [vectorLoading, setVectorLoading] = React.useState(false)

  const [hunterBriefing, setHunterBriefing] = React.useState<{ id: number; body: string } | null>(null)
  const hunterBriefSeq = React.useRef(0)

  const loadVaultStats = React.useCallback(async () => {
    setVaultLoading(true)
    try {
      const s = await fetchVaultStats()
      setVaultStats(s)
    } catch {
      setVaultStats(null)
    } finally {
      setVaultLoading(false)
    }
  }, [])

  const loadVectorMetrics = React.useCallback(async () => {
    setVectorLoading(true)
    try {
      const m = await invoke<DashboardMetrics>("get_dashboard_metrics", {
        workspacePath: workspacePath?.trim() ?? "",
      })
      setVectorMetrics(m)
    } catch {
      setVectorMetrics(null)
    } finally {
      setVectorLoading(false)
    }
  }, [workspacePath])

  const refreshVitals = React.useCallback(async () => {
    await Promise.all([loadVaultStats(), loadVectorMetrics()])
  }, [loadVaultStats, loadVectorMetrics])

  React.useEffect(() => {
    void refreshVitals()
  }, [refreshVitals])

  React.useEffect(() => {
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(VAULT_UPDATED_EVENT, (event) => {
        void (async () => {
          await refreshVitals()
          try {
            const stats = await fetchVaultStats()
            const alert = await fetchHunterAlertNotification(event.payload).catch(
              () => "**Hunter Alert**\n\nIngestion complete. Pull Environmental Context in Barney for a fresh triage."
            )
            hunterBriefSeq.current += 1
            setHunterBriefing({
              id: hunterBriefSeq.current,
              body: `${buildHunterBriefing(event.payload, stats)}\n\n${alert}`,
            })
          } catch {
            hunterBriefSeq.current += 1
            setHunterBriefing({
              id: hunterBriefSeq.current,
              body: buildHunterBriefing(event.payload, null),
            })
          }
        })()
      })
    })()
    return () => {
      unlisten?.()
    }
  }, [refreshVitals])

  React.useEffect(() => {
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(ARMORY_TOOL_MISSING_RESOURCE_EVENT, (event) => {
        const p = event.payload as { message?: string; tool?: string }
        const body =
          typeof p?.message === "string" && p.message.trim()
            ? `## Hunter's Alert\n\n${p.message.trim()}`
            : `## Hunter's Alert\n\nArmory tool **${String(p?.tool ?? "unknown")}** failed to launch — bundled \`Resource/scripts\` may be missing. Check the host log.`
        hunterBriefSeq.current += 1
        setHunterBriefing({ id: hunterBriefSeq.current, body })
      })
    })()
    return () => {
      unlisten?.()
    }
  }, [])

  React.useEffect(() => {
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(ARMORY_TOOL_STARTED_EVENT, (event) => {
        const p = event.payload as { target?: string; vaultDbPath?: string; type?: string }
        const t = typeof p?.target === "string" ? p.target.trim() : ""
        const label = t || "target"
        hunterBriefSeq.current += 1
        
        let body = ""
        if (p.type === "python") {
          body = `Launching native Python sync for ${label}...`
        } else if (p.type === "docker") {
          body = `Spinning up Docker container for ${label} intel gathering...`
        } else {
          body = `Initiating sync for ${label}...`
        }

        setHunterBriefing({
          id: hunterBriefSeq.current,
          body,
        })
      })
    })()
    return () => {
      unlisten?.()
    }
  }, [])

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  React.useEffect(() => {
    if (!lines.length) return
    const last = lines[lines.length - 1]?.message ?? ""
    const hit = triageFromConsoleLine(last)
    if (!hit) return
    if (consoleTriageFired.current.has(hit.key)) return
    consoleTriageFired.current.add(hit.key)
    hunterBriefSeq.current += 1
    setHunterBriefing({ id: hunterBriefSeq.current, body: hit.body })
  }, [lines])

  const scrollToHostConsole = React.useCallback(() => {
    hostConsoleRef.current?.scrollIntoView({ behavior: "smooth", block: "end" })
  }, [])

  const vaultPath = vaultStats?.vaultDbAbsolutePath?.trim()
    ? vaultStats.vaultDbAbsolutePath
    : null

  return (
    <div className="flex h-full min-h-0 min-w-0 flex-1 flex-col overflow-hidden bg-[oklch(0.07_0.01_260)] text-foreground">
      <VitalsBar
        workspacePath={workspacePath}
        vaultStats={vaultStats}
        vaultLoading={vaultLoading}
        vectorMetrics={vectorMetrics}
        vectorLoading={vectorLoading}
        model={model}
        baseUrl={baseUrl}
        showCenterMetrics={false}
        onIngestionHubClick={() => setIsVaultSettingsOpen((o) => !o)}
        vaultSettingsOpen={isVaultSettingsOpen}
        onOpenSettings={() => setSettingsOpen(true)}
        onOpenPalette={() => setPaletteOpen(true)}
        onOpenConsole={scrollToHostConsole}
        onSelectWorkspace={() => void selectWorkspace()}
      />

      <VaultSettingsOverlay open={isVaultSettingsOpen} onClose={() => setIsVaultSettingsOpen(false)} />

      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto overflow-x-hidden p-3 lg:flex-row lg:items-stretch lg:overflow-y-hidden lg:overflow-x-auto">
        {/* Left — Data Ingestion Hub + Armory */}
        <div ref={armoryAnchorRef} className={cn(PILLAR_BOX, PILLAR_FLEX_LEFT, "order-2 w-full lg:order-none")}>
          <div className="shrink-0 border-b border-white/10 px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Data ingestion hub
            </p>
            <p className="font-mono text-[9px] text-zinc-500">CVE / NVD sync and feeds · canonical vault path from vitals</p>
          </div>
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex min-h-0 flex-[3_1_0%] flex-col overflow-hidden px-1 pb-2 pt-1">
              <DataIngestionHub vaultDbAbsolutePath={vaultPath} />
            </div>
            <div className="flex min-h-0 flex-[2_1_0%] flex-col border-t border-white/10">
              <ProjectToolbox
                collapsed={false}
                onCollapsedChange={() => {}}
                onScriptActivity={bumpTelemetry}
                layoutVariant="pillar"
              />
            </div>
          </div>
        </div>

        {/* Center — Vitals pills · Barney (~70%) · Console (~30%) */}
        <div
          className={cn(
            PILLAR_BOX,
            PILLAR_FLEX_CENTER,
            "order-1 min-h-[70vh] w-full lg:order-none lg:min-h-0"
          )}
        >
          <div className="shrink-0 border-b border-white/10 px-3 py-2">
            <VitalsPills
              vaultStats={vaultStats}
              vaultLoading={vaultLoading}
              vectorMetrics={vectorMetrics}
              vectorLoading={vectorLoading}
            />
          </div>
          <div className="flex min-h-0 flex-[7_1_0%] flex-col overflow-hidden">
            <BarneyAgent
              layout="center"
              className="min-h-0 flex-1 rounded-none border-0 bg-transparent"
              onScriptActivity={bumpTelemetry}
              hunterBriefing={hunterBriefing}
            />
          </div>
          <div
            ref={hostConsoleRef}
            className="flex min-h-0 flex-[3_1_0%] flex-col overflow-hidden border-t border-white/10"
          >
            <SplitHostConsole />
          </div>
        </div>

        {/* Right — Live alerts / vault feed */}
        <div className={cn(PILLAR_BOX, PILLAR_FLEX_RIGHT, "order-3 w-full overflow-hidden lg:order-none")}>
          <LiveContextPanel pulseToken={pulseToken} layout="pillar" />
        </div>
      </div>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
      <OllamaSettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
    </div>
  )
}
