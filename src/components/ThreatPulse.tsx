"use client"

import React, { useEffect, useState } from "react"
import { listen } from "@tauri-apps/api/event"
import {
  fetchRecentAsmForFeed,
  fetchRecentCvesFromPulse,
  fetchRecentIocsFromPulse,
  fetchVaultStats,
  VAULT_UPDATED_EVENT,
  type VaultStats,
} from "@/lib/vault-search"
import { useWorkspace } from "./WorkspaceProvider"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card"
import { Badge } from "./ui/badge"
import { cvssNumeric, formatCvssBadge } from "@/lib/cvss-display"

interface CVEDTO {
  cve_id: string
  severity_score?: number | string | null
  description?: string
}

interface IocRecordRow {
  ioc_value: string
  ioc_type: string
  last_seen?: string
}

interface AsmRow {
  asset_target: string
  asset_type?: string
  last_scan_at?: string
  status?: string
}

const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })

export function ThreatPulse() {
  const { workspacePath } = useWorkspace()
  const [cves, setCves] = useState<CVEDTO[]>([])
  const [iocs, setIocs] = useState<IocRecordRow[]>([])
  const [assets, setAssets] = useState<AsmRow[]>([])
  const [vaultStats, setVaultStats] = useState<VaultStats | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchData() {
      try {
        const [recentCves, recentIocs, stats] = await Promise.all([
          fetchRecentCvesFromPulse(10),
          fetchRecentIocsFromPulse(10),
          fetchVaultStats().catch(() => null),
        ])
        setCves(recentCves)
        setIocs(
          recentIocs.map((r) => ({
            ioc_value: r.ioc_value,
            ioc_type: r.ioc_type,
            last_seen: r.last_seen,
          }))
        )
        setVaultStats(stats)
        if (workspacePath == null || workspacePath === "") {
          setAssets([])
          return
        }
        const recentAssets = await fetchRecentAsmForFeed(workspacePath, 5)
        setAssets(recentAssets)
      } catch (err) {
        setError(String(err))
      }
    }

    void fetchData()
    const interval = setInterval(() => void fetchData(), 60_000)
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(VAULT_UPDATED_EVENT, () => void fetchData())
    })()
    return () => {
      clearInterval(interval)
      unlisten?.()
    }
  }, [workspacePath])

  if (error) {
    return <div className="text-red-500">Error loading Threat Pulse: {error}</div>
  }

  const totalIocsLabel =
    vaultStats != null ? nf.format(vaultStats.iocRecords) : "—"

  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div>
            <CardTitle className="text-sm font-medium">Latest CVEs</CardTitle>
            <CardDescription className="text-[10px] text-muted-foreground">cti_vault.cve_data</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {cves.length > 0 ? (
              cves.map((cve) => (
                <div key={cve.cve_id} className="flex flex-col gap-1 border-b pb-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{cve.cve_id}</span>
                    <Badge
                      variant={
                        (cvssNumeric(cve.severity_score) ?? 0) > 7.0 ? "destructive" : "secondary"
                      }
                    >
                      {cve.severity_score != null && cve.severity_score !== ""
                        ? formatCvssBadge(cve.severity_score)
                        : "N/A"}
                    </Badge>
                  </div>
                  <span className="line-clamp-2 text-xs text-muted-foreground" title={cve.description}>
                    {cve.description}
                  </span>
                </div>
              ))
            ) : (
              <span className="text-xs italic text-muted-foreground">No CVE data in cve_data</span>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div>
            <CardTitle className="text-sm font-medium">IOC records</CardTitle>
            <CardDescription className="text-[10px] font-mono text-cyan-600/90">
              Total IOCs · {totalIocsLabel}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {iocs.length > 0 ? (
              iocs.map((r, i) => (
                <div key={`${r.ioc_value}-${i}`} className="flex items-center justify-between gap-2 border-b pb-2">
                  <span className="max-w-[140px] truncate font-semibold" title={r.ioc_value}>
                    {r.ioc_value}
                  </span>
                  <div className="flex shrink-0 flex-col items-end">
                    <Badge variant="outline">{r.ioc_type}</Badge>
                    <span className="text-xs text-muted-foreground">{r.last_seen ?? ""}</span>
                  </div>
                </div>
              ))
            ) : (
              <span className="text-xs italic text-muted-foreground">No IOC rows in ioc_records</span>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">ASM assets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {assets.length > 0 ? (
              assets.map((a, i) => (
                <div key={i} className="flex items-center justify-between gap-2 border-b pb-2">
                  <span className="max-w-[120px] truncate font-semibold" title={a.asset_target}>
                    {a.asset_target}
                  </span>
                  <div className="flex shrink-0 flex-col items-end">
                    <Badge variant="outline">{a.asset_type ?? "—"}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {a.status ?? ""} {a.last_scan_at ?? ""}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <span className="text-xs italic text-muted-foreground">
                {workspacePath ? "No ASM data" : "Set workspace for ASM feed"}
              </span>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
