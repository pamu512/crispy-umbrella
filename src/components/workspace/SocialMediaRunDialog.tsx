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
import { invokeRunProject, type SocialMediaRunParams } from "@/lib/run-project"

const DEFAULT_NUM = "10"

export function SocialMediaRunDialog({
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
  const [target, setTarget] = React.useState("")
  const [startDate, setStartDate] = React.useState("")
  const [endDate, setEndDate] = React.useState("")
  const [numPerPlatform, setNumPerPlatform] = React.useState(DEFAULT_NUM)
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
    const t = target.trim()
    if (!t) {
      setError("Enter a target name (keyword), same as ./docker-run.sh first argument.")
      return
    }
    setBusy(true)
    setError(null)
    const params: SocialMediaRunParams = {
      target: t,
      startDate: startDate.trim() || undefined,
      endDate: endDate.trim() || undefined,
      numPerPlatform: numPerPlatform.trim() || DEFAULT_NUM,
    }
    try {
      await invokeRunProject(workspacePath, "Social_MediaV2", "python", null, params, null, null, {
        scriptsRoot: scriptsRoot ?? undefined,
      })
      onStarted()
      onOpenChange(false)
      setTarget("")
      setStartDate("")
      setEndDate("")
      setNumPerPlatform(DEFAULT_NUM)
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
          <DialogTitle>Run Social Media V2</DialogTitle>
          <DialogDescription>
            Matches project <code className="font-mono text-xs">docker-run.sh</code>: target name,
            optional date window (<code className="font-mono text-xs">YYYY-MM-DD</code>), results per
            platform. CSVs go to <code className="font-mono text-xs">Social_MediaV2/output/</code>; on
            success, rows load into <code className="font-mono text-xs">cti_vault.social_media_results</code>.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-1">
          <div className="grid gap-1.5">
            <Label htmlFor="sm-target">Target name</Label>
            <Input
              id="sm-target"
              className="font-mono text-sm"
              placeholder='e.g. "Acme Corp" or Jack'
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoFocus
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="sm-start">Start date (optional)</Label>
              <Input
                id="sm-start"
                className="font-mono text-xs"
                placeholder="YYYY-MM-DD"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="sm-end">End date (optional)</Label>
              <Input
                id="sm-end"
                className="font-mono text-xs"
                placeholder="YYYY-MM-DD"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sm-num">Results per platform</Label>
            <Input
              id="sm-num"
              className="font-mono text-xs"
              value={numPerPlatform}
              onChange={(e) => setNumPerPlatform(e.target.value)}
            />
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
