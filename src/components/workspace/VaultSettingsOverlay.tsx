"use client"

import * as React from "react"
import { KeyRound, Loader2, Trash2, X } from "lucide-react"

import { useAppToast } from "@/components/app-toast"
import {
  clearIngestionSecret,
  getIngestionSecretStatuses,
  listIngestionSecretSlots,
  type IngestionSecretSlotMeta,
  saveIngestionSecret,
} from "@/lib/ingestion-secrets"
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

export type VaultSettingsOverlayProps = {
  open: boolean
  onClose: () => void
}

/**
 * Floating top-right panel: OS keychain credentials for ingestion (IntelX, Ransomware.live, RUMARK, EASM).
 */
export function VaultSettingsOverlay(props: VaultSettingsOverlayProps) {
  const { open, onClose } = props
  const toast = useAppToast()
  const [slots, setSlots] = React.useState<IngestionSecretSlotMeta[]>([])
  const [status, setStatus] = React.useState<Record<string, boolean>>({})
  const [rows, setRows] = React.useState<Record<string, string>>({})
  const [loading, setLoading] = React.useState(false)
  const [saving, setSaving] = React.useState<string | null>(null)
  const [clearing, setClearing] = React.useState<string | null>(null)

  const refresh = React.useCallback(async () => {
    setLoading(true)
    try {
      const [meta, st] = await Promise.all([
        listIngestionSecretSlots(),
        getIngestionSecretStatuses(),
      ])
      setSlots(meta)
      setStatus(st)
    } catch (err) {
      toast({
        variant: "error",
        title: "Could not load credential status",
        message: formatInvokeError(err),
      })
    } finally {
      setLoading(false)
    }
  }, [toast])

  React.useEffect(() => {
    if (!open) return
    queueMicrotask(() => {
      void refresh()
    })
  }, [open, refresh])

  React.useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault()
        onClose()
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open, onClose])

  const onSave = React.useCallback(
    async (service: string) => {
      const secret = (rows[service] ?? "").trim()
      if (!secret) {
        toast({
          variant: "error",
          title: "Secret required",
          message: "Paste the key or token before saving it to the OS keychain.",
        })
        return
      }
      setSaving(service)
      try {
        await saveIngestionSecret(service, secret)
        setRows((r) => ({ ...r, [service]: "" }))
        setStatus((s) => ({ ...s, [service]: true }))
        toast({
          variant: "success",
          title: "Credential saved",
          message: `Stored in the system keychain for service “${service}”.`,
        })
      } catch (err) {
        toast({
          variant: "error",
          title: "Save failed",
          message: formatInvokeError(err),
        })
      } finally {
        setSaving(null)
      }
    },
    [rows, toast]
  )

  const onClear = React.useCallback(
    async (service: string) => {
      setClearing(service)
      try {
        await clearIngestionSecret(service)
        setStatus((s) => ({ ...s, [service]: false }))
        toast({
          variant: "success",
          title: "Credential removed",
          message: `Keychain entry “${service}” was cleared.`,
        })
      } catch (err) {
        toast({
          variant: "error",
          title: "Clear failed",
          message: formatInvokeError(err),
        })
      } finally {
        setClearing(null)
      }
    },
    [toast]
  )

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[140]" role="presentation">
      <button
        type="button"
        aria-label="Close vault settings"
        className="absolute inset-0 bg-black/55 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />
      <div
        id="vault-settings-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vault-settings-title"
        className={cn(
          "absolute right-2 top-11 z-[141] flex max-h-[min(85vh,560px)] w-[min(100vw-1rem,22rem)] flex-col overflow-hidden rounded-lg border border-white/15 bg-zinc-950/92 shadow-[0_24px_80px_rgba(0,0,0,0.65)] backdrop-blur-md sm:right-3 sm:top-12 sm:w-[min(100vw-1.5rem,24rem)]"
        )}
        onMouseDown={(e) => e.stopPropagation()}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-start justify-between gap-2 border-b border-white/10 bg-black/30 px-3 py-2.5 sm:px-4">
          <div className="flex min-w-0 flex-1 items-start gap-2.5">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-white/12 bg-zinc-900/80 text-zinc-300">
              <KeyRound className="size-4" aria-hidden />
            </div>
            <div className="min-w-0">
              <h2 id="vault-settings-title" className="text-sm font-semibold tracking-tight text-zinc-100">
                Vault settings
              </h2>
              <p className="mt-0.5 font-mono text-[10px] leading-snug text-zinc-500">
                Keys stored in the OS credential manager (CTI-Command-Center). Sync actions read these when needed.
              </p>
            </div>
          </div>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="size-8 shrink-0 rounded-md border border-white/10 text-zinc-400 hover:bg-white/5 hover:text-zinc-100"
            onClick={onClose}
            aria-label="Close"
          >
            <X className="size-4" aria-hidden />
          </Button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-3 py-3 sm:px-4">
          {loading ? (
            <div className="flex items-center gap-2 py-6 font-mono text-xs text-zinc-500">
              <Loader2 className="size-4 animate-spin" aria-hidden />
              Loading keychain status…
            </div>
          ) : null}

          {!loading && slots.length === 0 ? (
            <Alert className="border-white/10 bg-zinc-900/50 py-2">
              <AlertTitle className="text-zinc-200">No credential slots</AlertTitle>
              <AlertDescription className="text-xs text-zinc-400">
                The host did not return ingestion metadata. Restart the desktop app after updating.
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="space-y-3">
            {slots.map((slot) => {
              const configured = !!status[slot.service]
              const busy = saving === slot.service || clearing === slot.service
              return (
                <div
                  key={slot.service}
                  className="rounded-md border border-white/10 bg-black/25 px-2.5 py-2.5 sm:px-3"
                >
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-medium text-zinc-200">{slot.label}</span>
                      <span
                        className={
                          "rounded px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide " +
                          (configured
                            ? "border border-emerald-500/35 bg-emerald-950/50 text-emerald-300"
                            : "border border-zinc-600/40 bg-zinc-950 text-zinc-500")
                        }
                      >
                        {configured ? "Saved" : "Not set"}
                      </span>
                    </div>
                    <p className="text-[10px] leading-snug text-zinc-500">{slot.description}</p>
                    <p className="font-mono text-[9px] text-zinc-600">
                      <span className="text-zinc-500">keychain</span> ·{" "}
                      <span className="text-zinc-400">{slot.service}</span>
                      {slot.envFallback ? (
                        <>
                          {" "}
                          · <span className="text-zinc-500">env</span>{" "}
                          <span className="text-zinc-400">{slot.envFallback}</span>
                        </>
                      ) : null}
                    </p>
                    <Label htmlFor={`vault-secret-${slot.service}`} className="sr-only">
                      {slot.label}
                    </Label>
                    <Input
                      id={`vault-secret-${slot.service}`}
                      type="password"
                      autoComplete="off"
                      value={rows[slot.service] ?? ""}
                      onChange={(e) =>
                        setRows((prev) => ({ ...prev, [slot.service]: e.target.value }))
                      }
                      disabled={busy}
                      placeholder={configured ? "New value to rotate…" : "Paste secret…"}
                      className="h-8 border-white/10 bg-zinc-950/80 font-mono text-[11px]"
                    />
                    <div className="flex flex-wrap gap-1.5">
                      <Button
                        type="button"
                        size="sm"
                        variant="secondary"
                        disabled={busy}
                        className="h-7 border border-white/10 bg-zinc-900 font-mono text-[10px]"
                        onClick={() => void onSave(slot.service)}
                      >
                        {saving === slot.service ? (
                          <Loader2 className="mr-1.5 size-3 animate-spin" aria-hidden />
                        ) : null}
                        Save to keychain
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        disabled={busy || !configured}
                        className="h-7 font-mono text-[10px] text-zinc-500 hover:text-red-300"
                        onClick={() => void onClear(slot.service)}
                      >
                        {clearing === slot.service ? (
                          <Loader2 className="mr-1.5 size-3 animate-spin" aria-hidden />
                        ) : (
                          <Trash2 className="mr-1 size-3 opacity-70" aria-hidden />
                        )}
                        Clear
                      </Button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="shrink-0 border-t border-white/10 bg-black/25 px-3 py-2 sm:px-4">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={loading}
            onClick={() => void refresh()}
            className="h-7 w-full border-white/12 bg-transparent font-mono text-[10px] text-zinc-400 hover:bg-white/5"
          >
            {loading ? <Loader2 className="mr-2 size-3 animate-spin" aria-hidden /> : null}
            Refresh status
          </Button>
        </div>
      </div>
    </div>
  )
}
