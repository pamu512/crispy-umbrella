"use client"

import * as React from "react"
import { runMacStealerNative } from "@/lib/ingestion-ipc"
import { useAppToast } from "@/components/app-toast"
import { Loader2, Shield } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

function formatInvokeError(err: unknown): string {
  if (typeof err === "string") return err
  if (err instanceof Error) return err.message
  return String(err)
}

/**
 * MAC / RUMARK-style stealer log fetch. Cookie may be pasted here or loaded from the OS keychain
 * (`mac_stealer_rumark_cookie`) via header · Ingestion hub → Vault settings.
 */
export function MacStealerForm() {
  const toast = useAppToast()
  const [cookie, setCookie] = React.useState("")
  const [domains, setDomains] = React.useState("")
  const [busy, setBusy] = React.useState(false)

  const onSubmit = React.useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault()
      const c = cookie.trim()
      const d = domains.trim()
      if (!d) {
        toast({
          variant: "error",
          title: "Domains required",
          message: "Enter at least one domain (comma-separated).",
        })
        return
      }
      setBusy(true)
      try {
        const out = await runMacStealerNative({
          ...(c ? { cookie: c } : {}),
          domains: d,
        })
        const preview = out.length > 800 ? `${out.slice(0, 800)}…` : out
        toast({
          variant: "success",
          title: "MAC Stealer sync completed",
          message: preview,
        })
        setCookie("")
      } catch (err) {
        toast({
          variant: "error",
          title: "MAC Stealer sync failed",
          message: formatInvokeError(err),
        })
      } finally {
        setBusy(false)
      }
    },
    [cookie, domains, toast]
  )

  return (
    <Card className="border-white/10 bg-zinc-950/80 shadow-none backdrop-blur-sm">
      <CardHeader className="space-y-1">
        <div className="flex items-center gap-2">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
            <Shield className="size-4" aria-hidden />
          </div>
          <div>
            <CardTitle className="text-base text-zinc-100">MAC stealer ingest</CardTitle>
            <CardDescription className="text-xs text-zinc-500">
              Fetches logs for the given email domains. Leave cookie blank to use the value saved in
              Vault settings. Typed cookie is masked and never stored in the
              browser or vault.
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <form onSubmit={onSubmit}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="mac-stealer-cookie" className="text-zinc-200">
              Session cookie
            </Label>
            <Input
              id="mac-stealer-cookie"
              name="mac_stealer_cookie"
              type="password"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              inputMode="text"
              placeholder="session=…; other=value"
              value={cookie}
              onChange={(e) => setCookie(e.target.value)}
              disabled={busy}
              className="border-white/10 bg-zinc-900/60 font-mono text-sm text-zinc-100 placeholder:text-zinc-600"
              aria-describedby="mac-stealer-cookie-hint"
            />
            <p id="mac-stealer-cookie-hint" className="text-xs text-zinc-500">
              Stored only in memory for this page session. Cleared after a successful run.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="mac-stealer-domains" className="text-zinc-200">
              Domains (comma-separated)
            </Label>
            <Input
              id="mac-stealer-domains"
              name="mac_stealer_domains"
              type="text"
              autoComplete="off"
              placeholder="example.com, victim.org"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              disabled={busy}
              className="border-white/10 bg-zinc-900/60 text-sm text-zinc-100 placeholder:text-zinc-600"
            />
          </div>
        </CardContent>
        <CardFooter className="flex justify-end border-t border-white/5 pt-4">
          <Button
            type="submit"
            disabled={busy}
            className="min-w-[9rem] bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-60"
          >
            {busy ? (
              <>
                <Loader2 className="mr-2 size-4 animate-spin" aria-hidden />
                Fetching…
              </>
            ) : (
              "Run fetch"
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}
