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
import { useWorkspace } from "@/components/WorkspaceProvider"
import { invokeRunProject, type IntelxRunParams } from "@/lib/run-project"

const DEFAULT_START = "2000-01-01"
const DEFAULT_END = "2099-12-31"
const DEFAULT_LIMIT = "2000"

export function IntelxRunDialog({
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
  const [query, setQuery] = React.useState("")
  const [startDate, setStartDate] = React.useState(DEFAULT_START)
  const [endDate, setEndDate] = React.useState(DEFAULT_END)
  const [searchLimit, setSearchLimit] = React.useState(DEFAULT_LIMIT)
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
    const q = query.trim()
    if (!q) {
      setError("Enter a search target (email, domain, or keyword).")
      return
    }
    setBusy(true)
    setError(null)
    const params: IntelxRunParams = {
      query: q,
      startDate: startDate.trim() || DEFAULT_START,
      endDate: endDate.trim() || DEFAULT_END,
      searchLimit: searchLimit.trim() || DEFAULT_LIMIT,
    }
    try {
      await invokeRunProject(workspacePath, "Intelx_Crawler", "sh", params, null, null, null, {
        scriptsRoot: scriptsRoot ?? undefined,
      })
      onStarted()
      onOpenChange(false)
      setQuery("")
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-panel max-w-md border-white/15 sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Run IntelX</DialogTitle>
          <DialogDescription>
            Docker Compose runs <code className="font-mono text-xs">intelx-scraper</code> with four
            stdin lines (same as bacongris workflow_runner): target, start date, end date, search limit.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-1">
          <div className="grid gap-1.5">
            <Label htmlFor="ix-query">Target</Label>
            <Input
              id="ix-query"
              className="font-mono text-sm"
              placeholder="email@domain.com or keyword"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoFocus
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="ix-start">Start date</Label>
              <Input
                id="ix-start"
                className="font-mono text-xs"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ix-end">End date</Label>
              <Input
                id="ix-end"
                className="font-mono text-xs"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ix-limit">Search limit</Label>
            <Input
              id="ix-limit"
              className="font-mono text-xs"
              value={searchLimit}
              onChange={(e) => setSearchLimit(e.target.value)}
            />
            <p className="text-[10px] text-muted-foreground">Max records / breadth for this run.</p>
          </div>
          {error ? (
            <p className="rounded border border-red-500/30 bg-red-950/20 p-2 font-mono text-[11px] text-red-200">
              {error}
            </p>
          ) : null}
        </div>
        <DialogFooter className="gap-2">
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="button" disabled={busy} onClick={() => void submit()}>
            {busy ? "Starting…" : "Run Docker job"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
