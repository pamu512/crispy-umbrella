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
import { useOllamaSettings } from "@/components/OllamaSettingsProvider"
import { ollamaTagsUrl, normalizeOllamaBaseUrl } from "@/lib/ollama-config"

export function OllamaSettingsDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
}) {
  const { baseUrl, model, persistSettings } = useOllamaSettings()
  const [draftBase, setDraftBase] = React.useState(baseUrl)
  const [draftModel, setDraftModel] = React.useState(model)
  const [testMsg, setTestMsg] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  React.useEffect(() => {
    if (open) {
      setDraftBase(baseUrl)
      setDraftModel(model)
      setTestMsg(null)
    }
  }, [open, baseUrl, model])

  const runTest = async () => {
    setBusy(true)
    setTestMsg(null)
    const root = normalizeOllamaBaseUrl(draftBase)
    try {
      const res = await fetch(ollamaTagsUrl(root), { method: "GET" })
      const text = await res.text()
      if (!res.ok) {
        setTestMsg(`HTTP ${res.status}: ${text.slice(0, 240)}`)
        return
      }
      let names: string[] = []
      try {
        const j = JSON.parse(text) as { models?: { name: string }[] }
        names = (j.models ?? []).map((m) => m.name).slice(0, 12)
      } catch {
        /* ignore */
      }
      setTestMsg(
        names.length
          ? `OK — local models (sample): ${names.join(", ")}${names.length >= 12 ? "…" : ""}`
          : "OK — connected (no models listed or unexpected JSON)."
      )
    } catch (e) {
      setTestMsg(`Network error: ${String(e)}`)
    } finally {
      setBusy(false)
    }
  }

  const applySave = async () => {
    setBusy(true)
    try {
      await persistSettings(draftBase, draftModel)
      onOpenChange(false)
    } catch (e) {
      setTestMsg(`Save failed: ${String(e)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-panel max-w-md border-white/15 sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Ollama</DialogTitle>
          <DialogDescription>
            HTTP 404 from <code className="font-mono text-xs">/api/chat</code> usually means the{" "}
            <strong>model tag</strong> is wrong or not pulled (
            <code className="font-mono text-xs">ollama pull llama3.1</code>).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="ollama-base">API base URL</Label>
            <Input
              id="ollama-base"
              className="font-mono text-xs"
              placeholder="http://127.0.0.1:11434"
              value={draftBase}
              onChange={(e) => setDraftBase(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground">
              No trailing path — only host and port (same as <code className="font-mono">OLLAMA_HOST</code>
              ).
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ollama-model">Model name</Label>
            <Input
              id="ollama-model"
              className="font-mono text-xs"
              placeholder="llama3.1"
              value={draftModel}
              onChange={(e) => setDraftModel(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground">
              Exact tag Ollama expects (e.g. <code className="font-mono">qwen2.5:7b</code>,{" "}
              <code className="font-mono">llama3.1:latest</code>).
            </p>
          </div>
          {testMsg ? (
            <p className="rounded-md border border-white/10 bg-black/40 p-2 font-mono text-[11px] leading-snug text-muted-foreground">
              {testMsg}
            </p>
          ) : null}
        </div>
        <DialogFooter className="gap-2 sm:justify-between">
          <Button type="button" variant="secondary" disabled={busy} onClick={() => void runTest()}>
            Test connection
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="button" disabled={busy} onClick={() => void applySave()}>
              Save
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
