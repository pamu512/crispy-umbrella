"use client"

import * as React from "react"
import { motion } from "framer-motion"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { cn } from "@/lib/utils"
import { listen } from "@tauri-apps/api/event"
import {
  fetchRecentAsmForFeed,
  fetchRecentCvesFromPulse,
  fetchRecentIocsFromPulse,
  VAULT_UPDATED_EVENT,
} from "@/lib/vault-search"
import { cvssNumeric, formatCvssBadge } from "@/lib/cvss-display"
import { Activity, Radio } from "lucide-react"

interface CVEDTO {
  cve_id: string
  severity_score?: number | string | null
  description?: string
}

interface IocRecordRow {
  ioc_value: string
  ioc_type: string
  last_seen?: string
  preview?: string
}

interface AsmRow {
  asset_target: string
  asset_type?: string
  last_scan_at?: string
  status?: string
}

function feedFingerprint(cves: CVEDTO[], iocs: IocRecordRow[], asm: AsmRow[]) {
  return `${cves[0]?.cve_id ?? ""}|${iocs[0]?.ioc_value ?? ""}|${asm[0]?.asset_target ?? ""}`
}

export function LiveContextPanel({
  pulseToken,
  layout = "sidebar",
}: {
  pulseToken: number
  /** `pillar` = equal-width dashboard column (no fixed 300px width). */
  layout?: "sidebar" | "pillar"
}) {
  const { workspacePath } = useWorkspace()
  const [cves, setCves] = React.useState<CVEDTO[]>([])
  const [iocs, setIocs] = React.useState<IocRecordRow[]>([])
  const [asm, setAsm] = React.useState<AsmRow[]>([])
  const [pulse, setPulse] = React.useState(false)
  const lastFp = React.useRef("")

  const load = React.useCallback(async () => {
    const nextCves = await fetchRecentCvesFromPulse(18)
    const rawIocs = await fetchRecentIocsFromPulse(18)
    const nextIocs: IocRecordRow[] = rawIocs.map((r) => ({
      ioc_value: r.ioc_value,
      ioc_type: r.ioc_type,
      last_seen: r.last_seen,
      preview: r.source_project ? `Source: ${r.source_project}` : undefined,
    }))
    const nextAsm = workspacePath ? await fetchRecentAsmForFeed(workspacePath, 18) : []

    const fp = feedFingerprint(nextCves, nextIocs, nextAsm)
    if (fp && fp !== lastFp.current) {
      lastFp.current = fp
      setPulse(true)
      window.setTimeout(() => setPulse(false), 1400)
    }
    setCves(nextCves)
    setIocs(nextIocs)
    setAsm(nextAsm)
  }, [workspacePath])

  React.useEffect(() => {
    void load()
    const t = window.setInterval(() => void load(), 45_000)
    let unlisten: (() => void) | undefined
    void (async () => {
      unlisten = await listen(VAULT_UPDATED_EVENT, () => void load())
    })()
    return () => {
      window.clearInterval(t)
      unlisten?.()
    }
  }, [load])

  React.useEffect(() => {
    if (pulseToken) void load()
  }, [pulseToken, load])

  const pillar = layout === "pillar"

  return (
    <motion.aside
      layout
      className={cn(
        "flex h-full min-h-0 shrink-0 flex-col bg-black/25",
        pillar ? "w-full min-w-0 border-0" : "w-[300px] border-l border-white/10"
      )}
    >
      <div className="flex h-11 items-center gap-2 border-b border-white/10 px-3">
        <Radio className="size-3.5 text-cyan-400" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Live alerts · CTI vault
        </span>
        <motion.span
          animate={{ opacity: pulse ? 1 : 0.35 }}
          className="ml-auto flex items-center gap-1 text-[9px] font-mono text-cyan-500/80"
        >
          <Activity className="size-3" />
          Live
        </motion.span>
      </div>
      <div className={cn("min-h-0 flex-1", pulse && "telemetry-pulse")}>
        <Tabs defaultValue="cve" className="flex h-full min-h-0 flex-1 flex-col overflow-hidden">
          <TabsList className="mx-2 mt-2 grid h-8 w-auto grid-cols-3 bg-black/40 p-0.5">
            <TabsTrigger value="cve" className="text-[10px] uppercase tracking-wide">
              CVE
            </TabsTrigger>
            <TabsTrigger value="ioc" className="text-[10px] uppercase tracking-wide">
              IOC
            </TabsTrigger>
            <TabsTrigger value="asm" className="text-[10px] uppercase tracking-wide">
              ASM
            </TabsTrigger>
          </TabsList>
          <TabsContent value="cve" className="mt-0 flex min-h-0 flex-1 flex-col px-0 pb-2">
            <ScrollArea className="min-h-0 flex-1 px-2">
              <div className="space-y-1.5 pt-2">
                {cves.length ? (
                  cves.map((cve) => {
                    const scoreN = cvssNumeric(cve.severity_score) ?? 0
                    return (
                      <div
                        key={cve.cve_id}
                        className="glass-panel rounded-md border border-white/5 px-2 py-1.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono text-[11px] font-medium text-foreground">
                            {cve.cve_id}
                          </span>
                          <Badge
                            variant="outline"
                            className={cn(
                              "h-5 shrink-0 px-1 font-mono text-[9px]",
                              scoreN >= 9 && "border-red-400/50 text-red-300",
                              scoreN >= 7 && scoreN < 9 && "border-amber-400/50 text-amber-200"
                            )}
                          >
                            {cve.severity_score != null && cve.severity_score !== ""
                              ? formatCvssBadge(cve.severity_score)
                              : "—"}
                          </Badge>
                        </div>
                        <p className="mt-0.5 line-clamp-2 font-mono text-[9px] leading-snug text-muted-foreground">
                          {cve.description}
                        </p>
                      </div>
                    )
                  })
                ) : (
                  <p className="px-2 py-6 text-center font-mono text-[10px] text-muted-foreground">
                    No CVE rows
                  </p>
                )}
              </div>
            </ScrollArea>
          </TabsContent>
          <TabsContent value="ioc" className="mt-0 flex min-h-0 flex-1 flex-col px-0 pb-2">
            <ScrollArea className="min-h-0 flex-1 px-2">
              <div className="space-y-1.5 pt-2">
                {iocs.length ? (
                  iocs.map((r, i) => (
                    <div
                      key={`${r.ioc_value}-${r.ioc_type}-${i}`}
                      className="glass-panel rounded-md border border-white/5 px-2 py-1.5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="line-clamp-2 break-all font-mono text-[10px] font-medium leading-tight">
                          {r.ioc_value}
                        </span>
                        <Badge variant="secondary" className="h-5 shrink-0 font-mono text-[8px]">
                          {r.ioc_type}
                        </Badge>
                      </div>
                      <p className="mt-0.5 line-clamp-2 font-mono text-[9px] text-muted-foreground">
                        {r.preview}
                      </p>
                      {r.last_seen ? (
                        <p className="mt-0.5 font-mono text-[8px] text-muted-foreground/70">{r.last_seen}</p>
                      ) : null}
                    </div>
                  ))
                ) : (
                  <p className="px-2 py-6 text-center font-mono text-[10px] text-muted-foreground">
                    No IOC rows in ioc_records (ingest or run an IOC source, then check again)
                  </p>
                )}
              </div>
            </ScrollArea>
          </TabsContent>
          <TabsContent value="asm" className="mt-0 flex min-h-0 flex-1 flex-col px-0 pb-2">
            <ScrollArea className="min-h-0 flex-1 px-2">
              <div className="space-y-1.5 pt-2">
                {asm.length ? (
                  asm.map((a) => (
                    <div
                      key={a.asset_target}
                      className="glass-panel rounded-md border border-white/5 px-2 py-1.5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="line-clamp-2 break-all font-mono text-[10px] font-medium leading-tight">
                          {a.asset_target}
                        </span>
                        <Badge variant="outline" className="h-5 shrink-0 font-mono text-[8px]">
                          {a.asset_type ?? "—"}
                        </Badge>
                      </div>
                      <div className="mt-0.5 flex items-center justify-between gap-2 font-mono text-[9px] text-muted-foreground">
                        <span>{a.status ?? "—"}</span>
                        <span>{a.last_scan_at ?? ""}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="px-2 py-6 text-center font-mono text-[10px] text-muted-foreground">
                    No ASM rows
                  </p>
                )}
              </div>
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </div>
    </motion.aside>
  )
}
