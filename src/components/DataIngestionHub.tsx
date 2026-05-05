"use client"

import * as React from "react"
import {
  AlertTriangle,
  Download,
  Loader2,
  Radar,
  Search,
  Shield,
  Skull,
} from "lucide-react"

import { useAppToast } from "@/components/app-toast"
import {
  handleSync,
  runCveSync,
  runIntelxSync,
  runMacStealerNative,
  runRansomwareNative,
} from "@/lib/ingestion-ipc"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

function formatInvokeError(err: unknown): string {
  if (typeof err === "string") return err
  if (err instanceof Error) return err.message
  return String(err)
}

function defaultStartDate(): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - 90)
  return d.toISOString().slice(0, 10)
}

function defaultEndDate(): string {
  return new Date().toISOString().slice(0, 10)
}

export type IngestionHubTab = "mac" | "ransom" | "asm" | "intelx" | "cve"

function IngestionTabPanel(props: { panelId: IngestionHubTab; children: React.ReactNode }) {
  return (
    <div
      id={`ing-panel-${props.panelId}`}
      role="tabpanel"
      aria-labelledby={`ing-tab-${props.panelId}`}
      className="flex min-h-0 flex-1 flex-col rounded-md border border-white/10 bg-zinc-950/70"
    >
      {props.children}
    </div>
  )
}

const TABS: {
  id: IngestionHubTab
  label: string
  short: string
  Icon: typeof Shield
}[] = [
  { id: "mac", label: "MAC Stealer", short: "MAC", Icon: Shield },
  { id: "ransom", label: "Ransomware.live", short: "Ransom", Icon: Skull },
  { id: "asm", label: "ASM", short: "ASM", Icon: Radar },
  { id: "intelx", label: "IntelX", short: "IntelX", Icon: Search },
  { id: "cve", label: "CVE / NVD", short: "CVE", Icon: Download },
]

/**
 * Tabbed ingestion controls for the left pillar: one tool visible at a time; keys in Vault settings (header).
 */
export function DataIngestionHub(props: { vaultDbAbsolutePath: string | null }) {
  const { vaultDbAbsolutePath } = props
  const toast = useAppToast()

  const vaultReady = !!vaultDbAbsolutePath?.trim()

  const withVaultPath = React.useCallback(
    <T extends Record<string, unknown>>(payload: T) =>
      vaultReady && vaultDbAbsolutePath
        ? { ...payload, vaultDbAbsolutePath: vaultDbAbsolutePath.trim() }
        : payload,
    [vaultDbAbsolutePath, vaultReady]
  )

  const [currentTab, setCurrentTab] = React.useState<IngestionHubTab>("mac")

  const [macCookie, setMacCookie] = React.useState("")
  const [macDomains, setMacDomains] = React.useState("")
  const [macBusy, setMacBusy] = React.useState(false)

  const [rwStart, setRwStart] = React.useState(defaultStartDate)
  const [rwEnd, setRwEnd] = React.useState(defaultEndDate)
  const [rwBusy, setRwBusy] = React.useState(false)

  const [asmDomain, setAsmDomain] = React.useState("")
  const [asmBusy, setAsmBusy] = React.useState(false)

  const [cveAction, setCveAction] = React.useState<"download" | "update" | "search">("update")
  const [cveSearchStart, setCveSearchStart] = React.useState(defaultStartDate)
  const [cveSearchEnd, setCveSearchEnd] = React.useState(defaultEndDate)
  const [cveVendor, setCveVendor] = React.useState("")
  const [cveBusy, setCveBusy] = React.useState(false)

  const [intelxTarget, setIntelxTarget] = React.useState("")
  const [intelxStart, setIntelxStart] = React.useState(defaultStartDate)
  const [intelxEnd, setIntelxEnd] = React.useState(defaultEndDate)
  const [intelxLimit, setIntelxLimit] = React.useState("2000")
  const [intelxBusy, setIntelxBusy] = React.useState(false)

  const onMacSync = React.useCallback(async () => {
    const d = macDomains.trim()
    if (!d) {
      toast({
        variant: "error",
        title: "Domains required",
        message: "Enter at least one domain (comma-separated).",
      })
      return
    }
    const c = macCookie.trim()
    setMacBusy(true)
    try {
      const out = await runMacStealerNative({
        domains: d,
        ...(c ? { cookie: c } : {}),
      })
      const preview = out.length > 800 ? `${out.slice(0, 800)}…` : out
      toast({
        variant: "success",
        title: "MAC Stealer sync completed",
        message: preview,
      })
    } catch (err) {
      toast({
        variant: "error",
        title: "MAC Stealer sync failed",
        message: formatInvokeError(err),
      })
    } finally {
      setMacBusy(false)
    }
  }, [macCookie, macDomains, toast])

  const onRansomwareSync = React.useCallback(async () => {
    setRwBusy(true)
    try {
      const out = await runRansomwareNative({
        startDate: rwStart.trim(),
        endDate: rwEnd.trim(),
      })
      const preview = out.length > 800 ? `${out.slice(0, 800)}…` : out
      toast({
        variant: "success",
        title: "Ransomware.live sync completed",
        message: preview,
      })
    } catch (err) {
      toast({
        variant: "error",
        title: "Ransomware.live sync failed",
        message: formatInvokeError(err),
      })
    } finally {
      setRwBusy(false)
    }
  }, [rwStart, rwEnd, toast])

  const onAsmSync = React.useCallback(async () => {
    const dom = asmDomain.trim().toLowerCase()
    if (!dom || !dom.includes(".")) {
      toast({
        variant: "error",
        title: "Invalid apex domain",
        message: "Enter a DNS apex such as example.com (no scheme or path).",
      })
      return
    }
    setAsmBusy(true)
    try {
      const n = await handleSync({ kind: "asm", payload: withVaultPath({ domain: dom }) })
      toast({
        variant: "success",
        title: "ASM scan completed",
        message: `Upserted ${n} asset row(s) into asm_assets. Shodan / Pentest-Tools: header · Vault settings.`,
      })
    } catch (err) {
      toast({
        variant: "error",
        title: "ASM scan failed",
        message: formatInvokeError(err),
      })
    } finally {
      setAsmBusy(false)
    }
  }, [asmDomain, withVaultPath, toast])

  const onIntelxSync = React.useCallback(async () => {
    const target = intelxTarget.trim()
    if (!target) {
      toast({
        variant: "error",
        title: "IntelX target missing",
        message: "Enter an email, domain, or keyword to search Intelligence X.",
      })
      return
    }
    setIntelxBusy(true)
    try {
      const out = await runIntelxSync({
        target,
        startDate: intelxStart.trim(),
        endDate: intelxEnd.trim(),
        limit: intelxLimit.trim() || "2000",
      })
      const preview = out.length > 800 ? `${out.slice(0, 800)}…` : out
      toast({
        variant: "success",
        title: "IntelX sync completed",
        message: preview,
      })
    } catch (err) {
      toast({
        variant: "error",
        title: "IntelX sync failed",
        message: formatInvokeError(err),
      })
    } finally {
      setIntelxBusy(false)
    }
  }, [intelxTarget, intelxStart, intelxEnd, intelxLimit, toast])

  const onCveSync = React.useCallback(async () => {
    if (!vaultReady) {
      toast({
        variant: "error",
        title: "Vault not ready",
        message: "Refresh the dashboard so the canonical vault path is available.",
      })
      return
    }
    if (cveAction === "search") {
      const sd = cveSearchStart.trim()
      const ed = cveSearchEnd.trim()
      const v = cveVendor.trim()
      if (!sd || !ed || !v) {
        toast({
          variant: "error",
          title: "Search parameters incomplete",
          message: "Provide start date, end date, and vendor (use * for all vendors).",
        })
        return
      }
    }
    setCveBusy(true)
    try {
      const out =
        cveAction === "search"
          ? await runCveSync({
              action: "search",
              startDate: cveSearchStart.trim(),
              endDate: cveSearchEnd.trim(),
              vendor: cveVendor.trim(),
            })
          : await runCveSync({ action: cveAction })
      const preview = out.length > 1200 ? `${out.slice(0, 1200)}…` : out
      toast({
        variant: "success",
        title:
          cveAction === "download"
            ? "CVE feeds downloaded"
            : cveAction === "update"
              ? "CVE feeds updated"
              : "CVE search finished",
        message: preview,
      })
    } catch (err) {
      toast({
        variant: "error",
        title: "CVE / NVD run failed",
        message: formatInvokeError(err),
      })
    } finally {
      setCveBusy(false)
    }
  }, [vaultReady, cveAction, cveSearchStart, cveSearchEnd, cveVendor, toast])

  const disabledVaultNative = !vaultReady
  const disabledCveNative = !vaultReady

  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden border-t border-white/10 bg-zinc-950/30 px-2 pb-2 pt-1.5">
      <div className="mb-1.5 shrink-0 space-y-0.5">
        <p className="text-[10px] leading-tight text-zinc-500">
          Keys · header <span className="font-mono text-zinc-400">Ingestion hub</span>
        </p>
        {vaultDbAbsolutePath ? (
          <p className="line-clamp-2 break-all font-mono text-[9px] text-zinc-600" title={vaultDbAbsolutePath}>
            {vaultDbAbsolutePath}
          </p>
        ) : null}
      </div>

      {disabledVaultNative ? (
        <Alert variant="destructive" className="mb-2 shrink-0 border-amber-500/40 bg-amber-950/30 py-2">
          <AlertTriangle className="size-3.5" />
          <AlertTitle className="text-[11px] text-amber-100">Vault path not loaded</AlertTitle>
          <AlertDescription className="font-mono text-[10px] text-amber-100/90">
            Refresh metrics before MAC / Ransom / ASM sync.
          </AlertDescription>
        </Alert>
      ) : null}

      <div
        role="tablist"
        aria-label="Ingestion tools"
        className="mb-1.5 flex shrink-0 gap-0.5 overflow-x-auto border-b border-white/10 pb-0.5 [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        {TABS.map(({ id, short, Icon }) => {
          const selected = currentTab === id
          return (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={selected}
              id={`ing-tab-${id}`}
              aria-controls={`ing-panel-${id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => setCurrentTab(id)}
              className={cn(
                "flex shrink-0 items-center gap-1 rounded-t border border-b-0 px-2 py-1 font-mono text-[10px] uppercase tracking-wide transition-colors",
                selected
                  ? "border-white/15 bg-zinc-900/90 text-zinc-100"
                  : "border-transparent bg-transparent text-zinc-500 hover:bg-white/5 hover:text-zinc-300"
              )}
            >
              <Icon className="size-3 shrink-0 opacity-90" aria-hidden />
              {short}
            </button>
          )
        })}
      </div>

      <div className="relative min-h-0 flex-1 overflow-hidden">
        {currentTab === "mac" && (
          <IngestionTabPanel panelId="mac">
              <div className="border-b border-white/10 px-2 py-1.5">
                <p className="font-mono text-[10px] leading-snug text-zinc-500">
                  <span className="text-zinc-400">Compromised_user_Mac</span> → ioc_records · cookie optional if saved in Vault
                </p>
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto px-2 py-2">
                <div className="space-y-1">
                  <Label htmlFor="hub-mac-cookie" className="text-[11px] text-zinc-400">
                    Session cookie
                  </Label>
                  <Input
                    id="hub-mac-cookie"
                    type="password"
                    autoComplete="off"
                    value={macCookie}
                    onChange={(e) => setMacCookie(e.target.value)}
                    disabled={macBusy || disabledVaultNative}
                    placeholder="Optional · or use Vault mac_stealer_rumark_cookie"
                    className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="hub-mac-domains" className="text-[11px] text-zinc-400">
                    Domains
                  </Label>
                  <Input
                    id="hub-mac-domains"
                    value={macDomains}
                    onChange={(e) => setMacDomains(e.target.value)}
                    disabled={macBusy || disabledVaultNative}
                    placeholder="example.com, other.org"
                    className="h-8 border-white/10 bg-zinc-900/70 text-[11px]"
                  />
                </div>
                <Button
                  type="button"
                  size="sm"
                  disabled={macBusy || disabledVaultNative}
                  onClick={() => void onMacSync()}
                  className="mt-1 h-8 w-full font-mono text-[11px]"
                >
                  {macBusy ? <Loader2 className="mr-2 size-3.5 animate-spin" /> : null}
                  Start sync
                </Button>
              </div>
          </IngestionTabPanel>
        )}

        {currentTab === "ransom" && (
          <IngestionTabPanel panelId="ransom">
              <div className="border-b border-white/10 px-2 py-1.5">
                <p className="font-mono text-[10px] leading-snug text-zinc-500">
                  PRO API via Vault <span className="text-zinc-400">ransomware_live</span> → ransomware_events
                </p>
              </div>
              <div className="flex flex-col gap-2 px-2 py-2">
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label htmlFor="hub-rw-start" className="text-[11px] text-zinc-400">
                      Start (UTC)
                    </Label>
                    <Input
                      id="hub-rw-start"
                      type="date"
                      value={rwStart}
                      onChange={(e) => setRwStart(e.target.value)}
                      disabled={rwBusy || disabledVaultNative}
                      className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="hub-rw-end" className="text-[11px] text-zinc-400">
                      End (UTC)
                    </Label>
                    <Input
                      id="hub-rw-end"
                      type="date"
                      value={rwEnd}
                      onChange={(e) => setRwEnd(e.target.value)}
                      disabled={rwBusy || disabledVaultNative}
                      className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                    />
                  </div>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={rwBusy || disabledVaultNative}
                  onClick={() => void onRansomwareSync()}
                  className="h-8 w-full font-mono text-[11px]"
                >
                  {rwBusy ? <Loader2 className="mr-2 size-3.5 animate-spin" /> : null}
                  Start sync
                </Button>
              </div>
          </IngestionTabPanel>
        )}

        {currentTab === "asm" && (
          <IngestionTabPanel panelId="asm">
              <div className="border-b border-white/10 px-2 py-1.5">
                <p className="font-mono text-[10px] leading-snug text-zinc-500">
                  Passive discovery → <span className="text-zinc-400">asm_assets</span>
                </p>
              </div>
              <div className="flex flex-col gap-2 px-2 py-2">
                <div className="space-y-1">
                  <Label htmlFor="hub-asm-domain" className="text-[11px] text-zinc-400">
                    Apex domain
                  </Label>
                  <Input
                    id="hub-asm-domain"
                    value={asmDomain}
                    onChange={(e) => setAsmDomain(e.target.value)}
                    disabled={asmBusy || disabledVaultNative}
                    placeholder="example.com"
                    className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                  />
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={asmBusy || disabledVaultNative}
                  onClick={() => void onAsmSync()}
                  className="h-8 w-full font-mono text-[11px]"
                >
                  {asmBusy ? <Loader2 className="mr-2 size-3.5 animate-spin" /> : null}
                  Start sync
                </Button>
              </div>
          </IngestionTabPanel>
        )}

        {currentTab === "intelx" && (
          <IngestionTabPanel panelId="intelx">
              <div className="border-b border-white/10 px-2 py-1.5">
                <p className="font-mono text-[10px] leading-snug text-zinc-500">
                  intelx_native_sync · API in Vault <span className="text-zinc-400">intelx_api_key</span>
                </p>
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto px-2 py-2">
                <div className="space-y-1">
                  <Label htmlFor="hub-intelx-target" className="text-[11px] text-zinc-400">
                    Target
                  </Label>
                  <Input
                    id="hub-intelx-target"
                    value={intelxTarget}
                    onChange={(e) => setIntelxTarget(e.target.value)}
                    disabled={intelxBusy || disabledVaultNative}
                    placeholder="email · domain · keyword"
                    className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label htmlFor="hub-intelx-start" className="text-[11px] text-zinc-400">
                      Start
                    </Label>
                    <Input
                      id="hub-intelx-start"
                      type="date"
                      value={intelxStart}
                      onChange={(e) => setIntelxStart(e.target.value)}
                      disabled={intelxBusy || disabledVaultNative}
                      className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="hub-intelx-end" className="text-[11px] text-zinc-400">
                      End
                    </Label>
                    <Input
                      id="hub-intelx-end"
                      type="date"
                      value={intelxEnd}
                      onChange={(e) => setIntelxEnd(e.target.value)}
                      disabled={intelxBusy || disabledVaultNative}
                      className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                    />
                  </div>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="hub-intelx-limit" className="text-[11px] text-zinc-400">
                    Limit
                  </Label>
                  <Input
                    id="hub-intelx-limit"
                    inputMode="numeric"
                    value={intelxLimit}
                    onChange={(e) => setIntelxLimit(e.target.value)}
                    disabled={intelxBusy || disabledVaultNative}
                    placeholder="2000"
                    className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                  />
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={intelxBusy || disabledVaultNative}
                  onClick={() => void onIntelxSync()}
                  className="h-8 w-full font-mono text-[11px]"
                >
                  {intelxBusy ? <Loader2 className="mr-2 size-3.5 animate-spin" aria-hidden /> : null}
                  Start sync
                </Button>
              </div>
          </IngestionTabPanel>
        )}

        {currentTab === "cve" && (
          <IngestionTabPanel panelId="cve">
              <div className="border-b border-white/10 px-2 py-1.5">
                <p className="font-mono text-[10px] leading-snug text-zinc-500">
                  <span className="text-zinc-400">CVE_Project_NVD/main.py</span> · bundled feeds — no ZIP URL here (use Download/Update/Search)
                </p>
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto px-2 py-2">
                <div className="space-y-1">
                  <Label htmlFor="hub-cve-action" className="text-[11px] text-zinc-400">
                    Action
                  </Label>
                  <select
                    id="hub-cve-action"
                    value={cveAction}
                    onChange={(e) =>
                      setCveAction(e.target.value as "download" | "update" | "search")
                    }
                    disabled={cveBusy || disabledCveNative}
                    className="flex h-8 w-full rounded-md border border-white/10 bg-zinc-900/70 px-2 py-1 font-mono text-[11px] text-zinc-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-500 disabled:opacity-50"
                  >
                    <option value="download">Download initial feeds</option>
                    <option value="update">Update feeds</option>
                    <option value="search">Search (dates + vendor)</option>
                  </select>
                </div>

                {cveAction === "search" ? (
                  <div className="grid grid-cols-1 gap-2">
                    <div className="space-y-1">
                      <Label htmlFor="hub-cve-start" className="text-[11px] text-zinc-400">
                        Start
                      </Label>
                      <Input
                        id="hub-cve-start"
                        value={cveSearchStart}
                        onChange={(e) => setCveSearchStart(e.target.value)}
                        disabled={cveBusy || disabledCveNative}
                        placeholder="YYYY-MM-DD"
                        className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="hub-cve-end" className="text-[11px] text-zinc-400">
                        End
                      </Label>
                      <Input
                        id="hub-cve-end"
                        value={cveSearchEnd}
                        onChange={(e) => setCveSearchEnd(e.target.value)}
                        disabled={cveBusy || disabledCveNative}
                        placeholder="YYYY-MM-DD"
                        className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="hub-cve-vendor" className="text-[11px] text-zinc-400">
                        Vendor(s)
                      </Label>
                      <Input
                        id="hub-cve-vendor"
                        value={cveVendor}
                        onChange={(e) => setCveVendor(e.target.value)}
                        disabled={cveBusy || disabledCveNative}
                        placeholder="*, comma list, etc."
                        className="h-8 border-white/10 bg-zinc-900/70 font-mono text-[11px]"
                      />
                    </div>
                  </div>
                ) : null}

                <Button
                  type="button"
                  size="sm"
                  disabled={cveBusy || disabledCveNative}
                  onClick={() => void onCveSync()}
                  className="h-8 w-full font-mono text-[11px]"
                >
                  {cveBusy ? <Loader2 className="mr-2 size-3.5 animate-spin" /> : null}
                  Start sync
                </Button>
              </div>
          </IngestionTabPanel>
        )}
      </div>
    </section>
  )
}
