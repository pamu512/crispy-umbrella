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
import { Textarea } from "@/components/ui/textarea"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { invokeRunProject, type CompromisedUserMacRunParams } from "@/lib/run-project"
import { useBundledScriptsRoot } from "@/lib/use-bundled-scripts-root"

export function CompromisedUserMacRunDialog({
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
  const effectiveScriptsRoot = useBundledScriptsRoot(scriptsRoot)
  const [domains, setDomains] = React.useState("")
  const [cookie, setCookie] = React.useState("")
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
    const d = domains.trim()
    if (!d) {
      setError("Enter at least one domain (comma-separated), e.g. example.com, foo.org")
      return
    }
    setBusy(true)
    setError(null)
    const params: CompromisedUserMacRunParams = {
      domains: d,
      cookie: cookie.trim() || undefined,
    }
    try {
      await invokeRunProject(
        workspacePath,
        "Compromised_user_Mac",
        "python",
        null,
        null,
        null,
        params,
        { scriptsRoot: effectiveScriptsRoot }
      )
      onStarted()
      onOpenChange(false)
      setDomains("")
      setCookie("")
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-panel max-w-md border-white/15 sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Native Mac Compromise (Rumark)</DialogTitle>
          <DialogDescription>
            Domains are sent to <code className="font-mono text-xs">main.py</code> as{" "}
            <code className="font-mono text-xs">RUMARK_DOMAINS</code>. Optional session cookie as{" "}
            <code className="font-mono text-xs">RUMARK_COOKIE</code>. Tor must be running for{" "}
            <code className="font-mono text-xs">RequestsTor</code>.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-1">
          <div className="grid gap-1.5">
            <Label htmlFor="rumark-domains">Domains (comma-separated)</Label>
            <Textarea
              id="rumark-domains"
              className="min-h-[88px] font-mono text-sm"
              placeholder="example.com, victim.org"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              autoFocus
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="rumark-cookie">Cookie (optional)</Label>
            <Input
              id="rumark-cookie"
              className="font-mono text-xs"
              placeholder="Paste session cookie if required"
              value={cookie}
              onChange={(e) => setCookie(e.target.value)}
            />
          </div>
          {error ? <p className="text-xs text-red-300">{error}</p> : null}
        </div>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="button" onClick={() => void submit()} disabled={busy}>
            {busy ? "Starting…" : "Initialize Hunter Sync."}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
