"use client"

import * as React from "react"
import { listen } from "@tauri-apps/api/event"
import { Activity, Database, RefreshCw, ShieldAlert, Skull, Target } from "lucide-react"

import { DataIngestionHub } from "@/components/DataIngestionHub"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { fetchVaultStats, type VaultStats, VAULT_UPDATED_EVENT } from "@/lib/vault-search"

export type DashboardMetrics = {
  totalIocs: number
  vulnerableAssets: number
  vectorDbConnected: boolean
  vectorDbCollectionReady: boolean
  vectorDbEndpoint: string
  vectorDbMessage: string
  vaultDbAbsolutePath: string
}

const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })

function MetricCard(props: {
  title: string
  description: string
  value: string
  icon: React.ReactNode
  accent: string
  loading?: boolean
}) {
  const { title, description, value, icon, accent, loading } = props
  return (
    <Card className="border-white/10 bg-zinc-950/80 shadow-none backdrop-blur-sm">
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
        <div className="space-y-1">
          <CardTitle className="text-sm font-medium text-zinc-100">{title}</CardTitle>
          <CardDescription className="text-xs text-zinc-500">{description}</CardDescription>
        </div>
        <div
          className={`flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 ${accent}`}
        >
          {icon}
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-9 w-28 animate-pulse rounded-md bg-zinc-800/80" aria-hidden />
        ) : (
          <p className="font-mono text-3xl font-semibold tracking-tight text-zinc-50 tabular-nums">{value}</p>
        )}
      </CardContent>
    </Card>
  )
}

export function OperationsOverview(props: {
  vectorMetrics: DashboardMetrics | null
  vectorLoading: boolean
  onRefreshVector: () => void
}) {
  const { workspacePath } = useWorkspace()
  const { vectorMetrics, vectorLoading, onRefreshVector } = props
  const [vault, setVault] = React.useState<VaultStats | null>(null)
  const [vaultLoading, setVaultLoading] = React.useState(false)
  const [vaultError, setVaultError] = React.useState<string | null>(null)

  const loadVault = React.useCallback(async () => {
    setVaultLoading(true)
    setVaultError(null)
    try {
      const s = await fetchVaultStats()
      setVault(s)
    } catch (e) {
      setVault(null)
      setVaultError(String(e))
    } finally {
      setVaultLoading(false)
    }
  }, [])

  React.useEffect(() => {
    void loadVault()
  }, [loadVault])

  React.useEffect(() => {
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(VAULT_UPDATED_EVENT, () => {
        void loadVault()
        onRefreshVector()
      })
    })()
    return () => {
      unlisten?.()
    }
  }, [loadVault, onRefreshVector])

  const refreshAll = React.useCallback(() => {
    void loadVault()
    onRefreshVector()
  }, [loadVault, onRefreshVector])

  const vectorStatusLabel = vectorMetrics
    ? vectorMetrics.vectorDbConnected
      ? vectorMetrics.vectorDbCollectionReady
        ? "CONNECTED (LOCAL)"
        : "LOCAL · NO TABLE"
      : "UNAVAILABLE"
    : vectorLoading
      ? "…"
      : "—"

  const vectorBadgeClass = vectorMetrics
    ? vectorMetrics.vectorDbConnected && vectorMetrics.vectorDbCollectionReady
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
      : vectorMetrics.vectorDbConnected
        ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
        : "border-red-500/40 bg-red-500/10 text-red-200"
    : "border-white/10 bg-zinc-900 text-zinc-400"

  const busy = vaultLoading || vectorLoading
  const vaultPath = vault?.vaultDbAbsolutePath

  return (
    <section
      className="shrink-0 border-b border-white/10 bg-gradient-to-b from-zinc-900/90 to-zinc-950/95 px-3 py-4 sm:px-4 sm:py-5"
      aria-labelledby="dashboard-heading"
    >
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 space-y-1">
            <h1 id="dashboard-heading" className="text-lg font-semibold tracking-tight text-zinc-50 sm:text-xl">
              Operations overview
            </h1>
            <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">CTI Command Center</p>
            <p className="max-w-2xl text-xs text-zinc-500 sm:text-sm">
              Vault row counts from <span className="font-mono">get_vault_stats</span> on the canonical SQLite file;
              vector status from the host probe.
            </p>
            <div className="space-y-1 rounded-md border border-white/10 bg-black/30 px-2 py-1.5">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                Active vault path (verify vs. ingestion logs)
              </p>
              <p
                className="break-all font-mono text-[10px] leading-snug text-cyan-200/90 sm:text-[11px]"
                title={vaultPath ?? "Load stats to resolve"}
              >
                {vaultLoading ? "Resolving vault path…" : vaultPath ?? "—"}
              </p>
              <p className="text-[10px] text-zinc-600">
                Host uses <span className="font-mono">CTI_DB_PATH</span> when set; otherwise{" "}
                <span className="font-mono">…/Documents/CTI_Command/cti_vault.db</span> (absolute only—same file as
                ingestion).
              </p>
            </div>
            {workspacePath ? (
              <p className="truncate font-mono text-[10px] text-zinc-600 sm:text-xs" title={workspacePath}>
                Workspace · {workspacePath}
              </p>
            ) : (
              <p className="text-xs text-zinc-500">
                Workspace optional for vault counts; required for CVE feed download path under your tree.
              </p>
            )}
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => void refreshAll()}
            className="h-9 shrink-0 border-white/15 bg-black/30 font-mono text-xs"
          >
            <RefreshCw className={`mr-2 size-3.5 ${busy ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {vaultError ? (
          <div
            role="alert"
            className="rounded-lg border border-red-500/30 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-100"
          >
            {vaultError}
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4 xl:grid-cols-4">
          <MetricCard
            title="Total IOCs"
            description="ioc_records"
            value={vault ? nf.format(vault.iocRecords) : "—"}
            icon={<Target className="size-4 text-sky-300" aria-hidden />}
            accent="bg-sky-500/10"
            loading={vaultLoading}
          />
          <MetricCard
            title="CVE records"
            description="cve_data"
            value={vault ? nf.format(vault.cveDataRows) : "—"}
            icon={<Skull className="size-4 text-rose-300" aria-hidden />}
            accent="bg-rose-500/10"
            loading={vaultLoading}
          />
          <MetricCard
            title="Asset–CVE mappings"
            description={`asset_cve_mapping rows · ${vault ? nf.format(vault.distinctAssetsWithCve) : "—"} distinct assets`}
            value={vault ? nf.format(vault.assetCveMappingRows) : "—"}
            icon={<ShieldAlert className="size-4 text-orange-300" aria-hidden />}
            accent="bg-orange-500/10"
            loading={vaultLoading}
          />
          <Card className="border-white/10 bg-zinc-950/80 shadow-none backdrop-blur-sm sm:col-span-2 xl:col-span-1">
            <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
              <div className="space-y-1">
                <CardTitle className="text-sm font-medium text-zinc-100">Vector database</CardTitle>
                <CardDescription className="text-xs text-zinc-500">
                  Local file-backed store (app data · vector_vault)—no separate vector daemon
                </CardDescription>
              </div>
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-violet-500/10">
                <Database className="size-4 text-violet-300" aria-hidden />
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wide ${vectorBadgeClass}`}
                >
                  <Activity className="mr-1 size-3 opacity-80" aria-hidden />
                  {vectorStatusLabel}
                </span>
                {vectorMetrics?.vectorDbCollectionReady ? (
                  <span className="font-mono text-[10px] text-zinc-500">collection ready</span>
                ) : null}
              </div>
              {vectorLoading ? (
                <div className="h-12 w-full animate-pulse rounded-md bg-zinc-800/80" aria-hidden />
              ) : vectorMetrics ? (
                <div className="space-y-1.5 font-mono text-[11px] leading-relaxed text-zinc-400">
                  <p className="break-all text-zinc-300">
                    <span className="text-zinc-500">endpoint </span>
                    {vectorMetrics.vectorDbEndpoint}
                  </p>
                  <p className="text-zinc-500">{vectorMetrics.vectorDbMessage}</p>
                </div>
              ) : (
                <p className="font-mono text-xs text-zinc-600">Refresh to load vector store status.</p>
              )}
            </CardContent>
          </Card>
        </div>

        <DataIngestionHub vaultDbAbsolutePath={vaultPath?.trim() ? vaultPath : null} />
      </div>
    </section>
  )
}
