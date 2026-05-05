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
import { runArmoryNativeAsmScan } from "@/lib/armory-ingest"
import { formatInvokeError } from "@/lib/invoke-error"

/**
 * Host EASM scan (`invoke_easm_scan`): seed domain is required; `window.prompt` is unreliable in Tauri WebViews.
 */
export function EasmNativeRunDialog(props: {
  open: boolean
  onOpenChange: (open: boolean) => void
  vaultDbAbsolutePath: string
  onBusyChange?: (busy: boolean) => void
  onSuccess: (result: { title: string; detail: string }) => void
  onError: (message: string) => void
}) {
  const { open, onOpenChange, vaultDbAbsolutePath, onBusyChange, onSuccess, onError } = props
  const [domain, setDomain] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (open) {
      setError(null)
      setBusy(false)
    }
  }, [open])

  const submit = async () => {
    const d = domain.trim()
    if (!d) {
      setError("Enter a seed domain (e.g. example.com).")
      return
    }
    setBusy(true)
    onBusyChange?.(true)
    setError(null)
    try {
      const result = await runArmoryNativeAsmScan({
        domain: d,
        vaultDbAbsolutePath,
      })
      onSuccess(result)
      setDomain("")
      onOpenChange(false)
    } catch (e) {
      const message = formatInvokeError(e)
      setError(message)
      onError(message)
    } finally {
      setBusy(false)
      onBusyChange?.(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-panel max-w-md border-white/15 sm:max-w-md">
        <DialogHeader>
          <DialogTitle>ASM scan (host)</DialogTitle>
          <DialogDescription>
            Runs the Tauri EASM pipeline into <span className="font-mono text-xs">asm_assets</span> on the
            canonical vault. Same path as the Data Lab ASM card.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-1">
          <div className="grid gap-1.5">
            <Label htmlFor="easm-domain">Seed domain</Label>
            <Input
              id="easm-domain"
              className="font-mono text-sm"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault()
                  void submit()
                }
              }}
            />
            <p className="text-[10px] text-muted-foreground">
              Root domain or hostname used to discover related assets (DNS / TLS / APIs per host scanner).
            </p>
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
            {busy ? "Scanning…" : "Initialize Hunter Sync."}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
