"use client"

import * as React from "react"
import { Activity, Database, FolderInput, Search, Settings, ShieldAlert, Target } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import type { DashboardMetrics } from "@/components/OperationsOverview"
import type { VaultStats } from "@/lib/vault-search"
import { cn } from "@/lib/utils"

const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })

/** IOC / CVE links / Vector pills — reusable above Barney or in the global vitals row. */
export function VitalsPills(props: {
  vaultStats: VaultStats | null
  vaultLoading: boolean
  vectorMetrics: DashboardMetrics | null
  vectorLoading: boolean
  className?: string
}) {
  const { vaultStats, vaultLoading, vectorMetrics, vectorLoading, className } = props

  const vectorStatusLabel = vectorMetrics
    ? vectorMetrics.vectorDbConnected
      ? vectorMetrics.vectorDbCollectionReady
        ? "VECTOR OK"
        : "VECTOR NO TABLE"
      : "VECTOR OFF"
    : vectorLoading
      ? "…"
      : "—"

  const vectorBadgeClass = vectorMetrics
    ? vectorMetrics.vectorDbConnected && vectorMetrics.vectorDbCollectionReady
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
      : vectorMetrics.vectorDbConnected
        ? "border-amber-500/40 bg-amber-500/10 text-amber-100"
        : "border-red-500/40 bg-red-500/10 text-red-100"
    : "border-white/10 bg-zinc-900 text-zinc-500"

  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-center gap-1.5 overflow-x-auto sm:gap-2",
        className
      )}
      role="group"
      aria-label="Vault and vector status"
    >
      <div
        className="flex items-center gap-1.5 rounded border border-white/10 bg-black/35 px-2 py-0.5 font-mono text-[9px] text-zinc-200"
        title="ioc_records"
      >
        <Target className="size-3 shrink-0 text-sky-400" aria-hidden />
        <span className="text-zinc-500">IOC</span>
        <span className="tabular-nums text-zinc-100">
          {vaultLoading ? "…" : vaultStats ? nf.format(vaultStats.iocRecords) : "—"}
        </span>
      </div>
      <div
        className="flex items-center gap-1.5 rounded border border-white/10 bg-black/35 px-2 py-0.5 font-mono text-[9px] text-zinc-200"
        title="Distinct assets in asset_cve_mapping"
      >
        <ShieldAlert className="size-3 shrink-0 text-orange-400" aria-hidden />
        <span className="text-zinc-500">CVE links</span>
        <span className="tabular-nums text-zinc-100">
          {vaultLoading ? "…" : vaultStats ? nf.format(vaultStats.distinctAssetsWithCve) : "—"}
        </span>
      </div>
      <div
        className={cn(
          "flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[9px]",
          vectorBadgeClass
        )}
        title={vectorMetrics?.vectorDbMessage ?? "Vector store"}
      >
        <Database className="size-3 shrink-0 opacity-90" aria-hidden />
        <span className="max-w-[100px] truncate sm:max-w-[140px]">{vectorStatusLabel}</span>
        <Activity className="size-3 shrink-0 opacity-70" aria-hidden />
      </div>
    </div>
  )
}

export function VitalsBar(props: {
  workspacePath: string | null
  vaultStats: VaultStats | null
  vaultLoading: boolean
  vectorMetrics: DashboardMetrics | null
  vectorLoading: boolean
  model: string
  baseUrl: string
  /** Toggles vault credential overlay (header “Ingestion hub”). */
  onIngestionHubClick: () => void
  /** When true, highlights the ingestion hub control (overlay open). */
  vaultSettingsOpen?: boolean
  onOpenSettings: () => void
  onOpenPalette: () => void
  onOpenConsole: () => void
  onSelectWorkspace: () => void
  /** When false, IOC/CVE/Vector pills are omitted (shown above Barney in the center pillar instead). */
  showCenterMetrics?: boolean
}) {
  const {
    workspacePath,
    vaultStats,
    vaultLoading,
    vectorMetrics,
    vectorLoading,
    model,
    baseUrl,
    onIngestionHubClick,
    vaultSettingsOpen = false,
    onOpenSettings,
    onOpenPalette,
    onOpenConsole,
    onSelectWorkspace,
    showCenterMetrics = true,
  } = props

  return (
    <header className="glass-panel z-30 flex h-10 shrink-0 items-center gap-2 border-b border-white/10 px-2 sm:gap-3 sm:px-3">
      <div className="flex min-w-0 flex-1 items-center gap-2 sm:gap-3">
        <span className="hidden shrink-0 text-[11px] font-semibold tracking-tight text-zinc-200 sm:inline">
          CTI
        </span>
        <Separator orientation="vertical" className="hidden h-5 bg-white/15 sm:block" />
        <span
          className="min-w-0 truncate font-mono text-[9px] text-muted-foreground sm:text-[10px]"
          title={workspacePath ?? "No workspace"}
        >
          {workspacePath ?? "Workspace · not set"}
        </span>
      </div>

      {showCenterMetrics ? (
        <div className="flex min-w-0 max-w-[38vw] flex-1 items-center justify-center sm:max-w-none sm:flex-[1.2]">
          <VitalsPills
            vaultStats={vaultStats}
            vaultLoading={vaultLoading}
            vectorMetrics={vectorMetrics}
            vectorLoading={vectorLoading}
          />
        </div>
      ) : (
        <div className="min-w-0 flex-1" aria-hidden />
      )}

      <div className="flex shrink-0 flex-wrap items-center justify-end gap-1 sm:gap-1.5">
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-expanded={vaultSettingsOpen}
          aria-haspopup="dialog"
          className={cn(
            "h-7 border-cyan-500/30 bg-cyan-950/30 px-2 font-mono text-[9px] text-cyan-100 hover:bg-cyan-950/50 sm:h-8 sm:text-[10px]",
            vaultSettingsOpen && "border-cyan-400/60 bg-cyan-950/55 ring-1 ring-cyan-400/35"
          )}
          onClick={onIngestionHubClick}
        >
          Ingestion hub
        </Button>
        <span
          className="hidden max-w-[100px] truncate font-mono text-[8px] text-muted-foreground xl:inline"
          title={`${baseUrl} · ${model}`}
        >
          {model}
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 border-white/15 bg-black/25 px-2 font-mono text-[9px] sm:h-8 sm:px-2.5 sm:text-[10px]"
          onClick={onOpenSettings}
        >
          <Settings className="mr-1 size-3 sm:size-3.5" />
          <span className="hidden sm:inline">Ollama</span>
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 border-white/15 bg-black/25 px-2 font-mono text-[9px] sm:h-8 sm:text-[10px]"
          onClick={onOpenPalette}
        >
          <Search className="mr-1 size-3 sm:size-3.5" />
          <span className="hidden sm:inline">Vault</span>
          <kbd className="ml-1 hidden rounded border border-white/20 bg-black/40 px-1 font-mono text-[8px] sm:inline">
            ⌘K
          </kbd>
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 border-white/15 bg-black/25 px-2 font-mono text-[9px] sm:h-8 sm:text-[10px]"
          onClick={onOpenConsole}
        >
          Console
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 font-mono text-[9px] text-muted-foreground sm:h-8 sm:text-[10px]"
          onClick={() => void onSelectWorkspace()}
        >
          <FolderInput className="mr-1 size-3 sm:size-3.5" />
          <span className="hidden sm:inline">Workspace</span>
        </Button>
      </div>
    </header>
  )
}
