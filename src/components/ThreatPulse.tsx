"use client"

import React, { useEffect, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import { useWorkspace } from "./WorkspaceProvider"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
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

export function ThreatPulse() {
  const { workspacePath } = useWorkspace()
  const [cves, setCves] = useState<CVEDTO[]>([])
  const [iocs, setIocs] = useState<IocRecordRow[]>([])
  const [assets, setAssets] = useState<AsmRow[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!workspacePath) return
    
    async function fetchData() {
      try {
        const recentCves = await invoke<CVEDTO[]>("query_db", {
          workspacePath,
          query: `SELECT cve_id, severity_score,
            COALESCE(json_extract(metadata, '$.description'), '') AS description
            FROM cve_data
            ORDER BY datetime(COALESCE(NULLIF(updated_at, ''), published_date)) DESC, cve_id DESC LIMIT 5`,
        }).catch(() => [])

        const recentIocs = await invoke<IocRecordRow[]>("query_db", {
          workspacePath,
          query: `SELECT ioc_value, ioc_type, last_seen FROM ioc_records
            ORDER BY datetime(COALESCE(NULLIF(last_seen, ''), first_seen)) DESC LIMIT 5`,
        }).catch(() => [])

        const recentAssets = await invoke<AsmRow[]>("query_db", {
          workspacePath,
          query: `SELECT asset_target, asset_type, last_scan_at, status FROM asm_assets
            ORDER BY datetime(COALESCE(NULLIF(last_scan_at, ''), '')) DESC LIMIT 5`,
        }).catch(() => [])

        setCves(recentCves)
        setIocs(recentIocs)
        setAssets(recentAssets)
      } catch (err) {
        setError(String(err))
      }
    }
    
    fetchData()
    const interval = setInterval(fetchData, 60000)
    return () => clearInterval(interval)
  }, [workspacePath])

  if (error) {
    return <div className="text-red-500">Error loading Threat Pulse: {error}</div>
  }

  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Latest CVEs</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {cves.length > 0 ? cves.map(cve => (
              <div key={cve.cve_id} className="flex flex-col gap-1 border-b pb-2">
                <div className="flex justify-between items-center">
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
                <span className="text-xs text-muted-foreground line-clamp-2" title={cve.description}>{cve.description}</span>
              </div>
            )) : <span className="text-muted-foreground text-xs italic">No CVE data available</span>}
          </div>
        </CardContent>
      </Card>
      
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">IOC records</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {iocs.length > 0 ? iocs.map((r, i) => (
              <div key={i} className="flex justify-between items-center border-b pb-2 gap-2">
                <span className="font-semibold truncate max-w-[140px]" title={r.ioc_value}>{r.ioc_value}</span>
                <div className="flex flex-col items-end shrink-0">
                  <Badge variant="outline">{r.ioc_type}</Badge>
                  <span className="text-xs text-muted-foreground">{r.last_seen ?? ""}</span>
                </div>
              </div>
            )) : <span className="text-muted-foreground text-xs italic">No IOC records</span>}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">ASM assets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            {assets.length > 0 ? assets.map((a, i) => (
              <div key={i} className="flex justify-between items-center border-b pb-2 gap-2">
                <span className="font-semibold truncate max-w-[120px]" title={a.asset_target}>{a.asset_target}</span>
                <div className="flex flex-col items-end shrink-0">
                  <Badge variant="outline">{a.asset_type ?? "—"}</Badge>
                  <span className="text-xs text-muted-foreground">{a.status ?? ""} {a.last_scan_at ?? ""}</span>
                </div>
              </div>
            )) : <span className="text-muted-foreground text-xs italic">No ASM data</span>}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
