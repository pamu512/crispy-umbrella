"use client"

import * as React from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { invokeRunProject, type PhishingRunParams, type PhishingScanType } from "@/lib/run-project"

export function PhishingRunDialog({
  open,
  onOpenChange,
  workspacePath,
  onStarted,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  workspacePath: string | null
  onStarted: () => void
}) {
  const { scriptsRoot } = useWorkspace()
  const [scanType, setScanType] = React.useState<PhishingScanType>("PS")
  const [domains, setDomains] = React.useState("")
  const [keywords, setKeywords] = React.useState("")
  const [startDate, setStartDate] = React.useState("")
  const [endDate, setEndDate] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (open) {
      setError(null)
      setBusy(false)
    }
  }, [open])

  const submit = async () => {
    if (!workspacePath) return
    const s = startDate.trim()
    const e = endDate.trim()
    if (!s || !e) {
      setError("Start and end dates are required (YYYY-MM-DD).")
      return
    }
    if (scanType === "PS" || scanType === "ALL") {
      if (!domains.trim()) {
        setError("Domain(s) are required for PS and ALL (comma-separated, e.g. example.com, other.org).")
        return
      }
      const domainList = domains
        .split(",")
        .map((d) => d.trim())
        .filter(Boolean)
      const missingDot = domainList.filter((d) => !d.includes("."))
      if (missingDot.length > 0) {
        setError(
          `Use full domains for phishing scans (include a TLD), e.g. lalamove.com — not: ${missingDot.join(", ")}`
        )
        return
      }
    }
    if (scanType === "SMS" || scanType === "ALL") {
      if (!keywords.trim()) {
        setError("Keyword(s) are required for SMS and ALL (comma-separated).")
        return
      }
    }
    setBusy(true)
    setError(null)
    const params: PhishingRunParams = {
      scanType,
      domains: domains.trim() || undefined,
      keywords: keywords.trim() || undefined,
      startDate: s,
      endDate: e,
    }
    try {
      await invokeRunProject(
        workspacePath,
        "Phishing_and_Social_Media_All-in-one",
        "python",
        null,
        null,
        params,
        null,
        { scriptsRoot: scriptsRoot ?? undefined }
      )
      onStarted()
      onOpenChange(false)
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-panel max-w-md border-white/15 sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Run Brand Scout (Phishing+)</DialogTitle>
          <DialogDescription>
            Matches <code className="font-mono text-xs">brand_scout.py</code> / README: choose{" "}
            <strong>PS</strong> (domains), <strong>SMS</strong> (keywords), or <strong>ALL</strong>, plus
            date range. Docker-heavy steps (e.g. domain-sift) still require Docker images on the host.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-1">
          <div className="grid gap-1.5">
            <Label htmlFor="ph-scan">Scan type</Label>
            <select
              id="ph-scan"
              className={cn(
                "h-9 w-full rounded-md border border-white/15 bg-black/40 px-2 font-mono text-xs",
                "text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/60"
              )}
              value={scanType}
              onChange={(e) => setScanType(e.target.value as PhishingScanType)}
            >
              <option value="PS">PS — Phishing scan (domains)</option>
              <option value="SMS">SMS — Social media scan (keywords)</option>
              <option value="ALL">ALL — Both</option>
            </select>
          </div>
          {(scanType === "PS" || scanType === "ALL") && (
            <div className="grid gap-1.5">
              <Label htmlFor="ph-domains">Domain(s)</Label>
              <Input
                id="ph-domains"
                className="font-mono text-sm"
                placeholder="example.com, other.org"
                value={domains}
                onChange={(e) => setDomains(e.target.value)}
              />
            </div>
          )}
          {(scanType === "SMS" || scanType === "ALL") && (
            <div className="grid gap-1.5">
              <Label htmlFor="ph-keywords">Keyword(s)</Label>
              <Input
                id="ph-keywords"
                className="font-mono text-sm"
                placeholder="brand, product name"
                value={keywords}
                onChange={(e) => setKeywords(e.target.value)}
              />
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="ph-start">Start date</Label>
              <Input
                id="ph-start"
                className="font-mono text-xs"
                placeholder="YYYY-MM-DD"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ph-end">End date</Label>
              <Input
                id="ph-end"
                className="font-mono text-xs"
                placeholder="YYYY-MM-DD"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>
          {error ? <p className="text-xs text-red-300">{error}</p> : null}
        </div>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="button" onClick={() => void submit()} disabled={busy}>
            {busy ? "Starting…" : "Run"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
