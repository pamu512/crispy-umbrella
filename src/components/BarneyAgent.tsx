"use client"

import * as React from "react"
import { invoke } from "@tauri-apps/api/core"
import { Eraser, Loader2, Send } from "lucide-react"

import { AGENT_TAGLINE } from "@/components/Sidebar"
import { useOllamaSettings } from "@/components/OllamaSettingsProvider"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Textarea } from "@/components/ui/textarea"
import { cn } from "@/lib/utils"
import { sanitizeBarneyAssistantText } from "@/lib/barney-reply-sanitize"
import {
  fetchBarneyEnvironmentalContext,
  fetchRecentCvesFromPulse,
  fetchVaultStats,
  type VaultStats,
} from "@/lib/vault-search"

type ChatRole = "user" | "assistant"

export type BarneyMessage = {
  id: string
  role: ChatRole
  content: string
}

type SemanticThreatHit = {
  score: number
  sqliteRowid: number
  iocValue: string
  iocType: string
  firstSeen?: string | null
  lastSeen?: string | null
  sourceProject?: string | null
  metadata?: string | null
}

function newMessageId(): string {
  return `barney_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`
}

function extractLlmContent(data: unknown): string {
  if (typeof data !== "object" || data === null) {
    return typeof data === "string" ? data : String(data)
  }
  const d = data as Record<string, unknown>
  const msg = d.message as Record<string, unknown> | undefined
  if (msg && typeof msg.content === "string") {
    return msg.content.trim()
  }
  if (typeof d.response === "string") {
    return d.response.trim()
  }
  return JSON.stringify(data, null, 2).slice(0, 12_000)
}

const BARNEY_SYSTEM =
  "You are **Barney**, the standalone CTI Command Center's local co-pilot and expert **cyber threat hunter**—not a generic assistant. " +
  "**You are now the central nervous system of the CTI Command Center.** You sit between the **Ingestion Hub** (Armory / sync controls) on your left and **Live alerts · CTI vault** on your right; beneath you flows the **Host console** — treat errors there as tactical signals: explain fixes (API keys, Docker, Python env) in plain steps. " +
  "Voice: proactive, vigilant, slightly gritty (watch-floor energy). You live for signals: lateral movement, blast radius, pivot points, and exploitation likelihood (CVE → asset → credential → leak). " +
  "Use the center stage: headings, tight bullets, fenced blocks and pseudo-tables when they sharpen risk. " +
  "When the Armory lands fresh telemetry or the host sends a **cti_vault watch** snapshot without the operator typing, treat it as orders to brief: what moved, why it could hurt, and the next pivot (e.g. IntelX for leaked creds, ASM pressure-test, correlation pass). " +
  "You may suggest chains like: spike in CVEs touching the ASM stack → pivot IntelX for those org strings / domains → validate in vault. Be concrete; no permission-theater—tell them what you'd hit next. " +
  "Stay concise, accurate, and security-aware. Ground answers in any vault context supplied in separate system messages. " +
  "**Never** print meta-rubrics, sentence-count rules, or stylistic instructions to yourself—especially not wrapped in asterisks or parentheses (e.g. `*(4 sentences, gritty…)*`). The operator sees only analyst-ready prose."

const VAULT_SYSTEM_PREAMBLE =
  "The following block is semantic / IOC context from the local CTI Command Center vault (cti_vault / embeddings). " +
  "Read it like hunt traffic: tie IOCs to movement hypotheses and next pivots. If the block is empty, say so briefly—then one line on what you'd watch next."

const VAULT_WATCH_USER_PROMPT =
  "[INTERNAL — OPERATOR MAY BE IDLE] The host just refreshed a **cti_vault watch** snapshot in your system context. " +
  "Reply with **one** unsolicited watch-floor message (2–6 sentences), gritty Barney tone. " +
  "Call out spikes, CVE↔ASM exposure angles, lateral movement guesses, or exploitation likelihood. " +
  "If the vault is quiet, still say what you'd keep an eye on and one low-effort habit (e.g. re-pull NVD delta, spot-check top assets). " +
  "Do not meta-talk about being an AI or the watch timer. " +
  "Do **not** prefix or suffix your reply with format rubrics (`*(…)*`)—give the watch-floor line only."

const WATCH_FIRST_MS = 90_000
const WATCH_INTERVAL_MS = 12 * 60 * 1000
const WATCH_MIN_GAP_MS = 6 * 60 * 1000

function formatVaultWatchBlock(
  stats: VaultStats,
  recent: { cve_id: string; severity_score?: number | string | null; description?: string }[]
): string {
  const top = recent
    .slice(0, 6)
    .map(
      (r, i) =>
        `${i + 1}. ${r.cve_id} · CVSS/base=${r.severity_score ?? "—"} · ${(r.description ?? "").slice(0, 140).replace(/\s+/g, " ")}`
    )
    .join("\n")
  return [
    `vault_path=${stats.vaultDbAbsolutePath}`,
    `ioc_records=${stats.iocRecords}`,
    `cve_data_rows=${stats.cveDataRows}`,
    `asset_cve_mapping_rows=${stats.assetCveMappingRows}`,
    `distinct_assets_with_cve=${stats.distinctAssetsWithCve}`,
    "",
    "Recent CVE pulse (sample):",
    top || "(no recent CVE rows in pulse sample)",
  ].join("\n")
}

function formatHitsForLlm(hits: SemanticThreatHit[]): string {
  if (!hits.length) {
    return "No semantic vault matches for this query (empty result set)."
  }
  const lines = hits.map((h, i) => {
    const meta = h.metadata?.trim()
    return [
      `${i + 1}. score=${h.score.toFixed(4)} rowid=${h.sqliteRowid}`,
      `   IOC: ${h.iocValue} (${h.iocType})`,
      `   first_seen=${h.firstSeen ?? "—"} last_seen=${h.lastSeen ?? "—"} source=${h.sourceProject ?? "—"}`,
      meta ? `   metadata: ${meta}` : null,
    ]
      .filter(Boolean)
      .join("\n")
  })
  return lines.join("\n\n")
}

export function BarneyAgent({
  className,
  onScriptActivity,
  layout = "rail",
  hunterBriefing,
}: {
  className?: string
  /** Optional hook (e.g. telemetry pulse) after a successful round-trip. */
  onScriptActivity?: () => void
  /** `center` = hunter-first main stage (wider bubbles, lighter chrome). */
  layout?: "rail" | "center"
  /** When `id` changes, an assistant “hunter’s briefing” message is appended (e.g. after vault ingest). */
  hunterBriefing?: { id: number; body: string } | null
}) {
  const { model, baseUrl } = useOllamaSettings()
  const [messages, setMessages] = React.useState<BarneyMessage[]>([])
  const [includeVaultData, setIncludeVaultData] = React.useState(false)
  const [draft, setDraft] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [busyPhase, setBusyPhase] = React.useState<"idle" | "vault" | "context" | "llm">("idle")
  const scrollRootRef = React.useRef<HTMLDivElement>(null)
  const lastHunterBriefId = React.useRef<number | null>(null)
  const busyRef = React.useRef(false)
  const proactiveInFlightRef = React.useRef(false)
  const lastProactiveAtRef = React.useRef<number>(0)

  const center = layout === "center"

  React.useEffect(() => {
    busyRef.current = busy
  }, [busy])

  const runVaultWatchNudge = React.useCallback(async () => {
    if (!center) return
    const modelTag = model.trim()
    if (!modelTag || proactiveInFlightRef.current || busyRef.current) return
    const now = Date.now()
    if (lastProactiveAtRef.current && now - lastProactiveAtRef.current < WATCH_MIN_GAP_MS) return

    proactiveInFlightRef.current = true
    try {
      const stats = await fetchVaultStats()
      const recent = await fetchRecentCvesFromPulse(8)
      const watchBlock = formatVaultWatchBlock(stats, recent)
      let envBlock = ""
      try {
        envBlock = (await fetchBarneyEnvironmentalContext()).trim()
      } catch {
        envBlock = "_Environmental Context unavailable._"
      }
      const ollamaHost = baseUrl.trim() || undefined
      const data = await invoke<unknown>("invoke_local_llm", {
        payload: {
          messages: [
            {
              role: "system",
              content: `${BARNEY_SYSTEM}\n\n## Environmental Context (live SQLite cti_vault)\n\n${envBlock}\n\n## cti_vault watch (host snapshot)\n${watchBlock}`,
            },
            { role: "user", content: VAULT_WATCH_USER_PROMPT },
          ],
          model: modelTag,
          ollamaHost,
        },
      })
      const content = sanitizeBarneyAssistantText(extractLlmContent(data))
      if (content) {
        setMessages((m) => [
          ...m,
          {
            id: newMessageId(),
            role: "assistant",
            content,
          },
        ])
        onScriptActivity?.()
      }
      lastProactiveAtRef.current = Date.now()
    } catch {
      /* watch tick is best-effort */
    } finally {
      proactiveInFlightRef.current = false
    }
  }, [baseUrl, center, model, onScriptActivity])

  React.useEffect(() => {
    if (!center) return
    const tick = () => {
      if (typeof document !== "undefined" && document.hidden) return
      if (busyRef.current || proactiveInFlightRef.current) return
      void runVaultWatchNudge()
    }
    const t0 = window.setTimeout(tick, WATCH_FIRST_MS)
    const id = window.setInterval(tick, WATCH_INTERVAL_MS)
    return () => {
      window.clearTimeout(t0)
      window.clearInterval(id)
    }
  }, [center, runVaultWatchNudge])

  React.useEffect(() => {
    if (!hunterBriefing) return
    if (lastHunterBriefId.current === hunterBriefing.id) return
    lastHunterBriefId.current = hunterBriefing.id
    setMessages((m) => [
      ...m,
      {
        id: newMessageId(),
        role: "assistant",
        content: hunterBriefing.body,
      },
    ])
  }, [hunterBriefing])

  const scrollToBottom = React.useCallback(() => {
    const root = scrollRootRef.current
    if (!root) return
    const viewport = root.querySelector("[data-radix-scroll-area-viewport]") as HTMLElement | null
    if (viewport) {
      viewport.scrollTop = viewport.scrollHeight
    }
  }, [])

  React.useLayoutEffect(() => {
    scrollToBottom()
  }, [messages, busy, busyPhase, scrollToBottom])

  const clearContext = React.useCallback(() => {
    setMessages([])
    setDraft("")
  }, [])

  const send = React.useCallback(async () => {
    const text = draft.trim()
    if (!text || busy) return

    const ollamaHost = baseUrl.trim() || undefined
    const modelTag = model.trim() || undefined

    const userMsg: BarneyMessage = { id: newMessageId(), role: "user", content: text }
    const transcript = [...messages, userMsg]
    setDraft("")
    setMessages(transcript)
    setBusy(true)
    setBusyPhase(includeVaultData ? "vault" : "llm")

    const thread = transcript.filter((m) => m.role === "user" || m.role === "assistant")

    try {
      let vaultBlock: string | undefined
      if (includeVaultData) {
        setBusyPhase("vault")
        const hits = await invoke<SemanticThreatHit[]>("semantic_threat_search", { query: text })
        vaultBlock = `${VAULT_SYSTEM_PREAMBLE}\n\n${formatHitsForLlm(Array.isArray(hits) ? hits : [])}`
      }

      setBusyPhase("context")
      let envBlock = ""
      try {
        envBlock = (await fetchBarneyEnvironmentalContext()).trim()
      } catch {
        envBlock = "_Environmental Context unavailable (vault read failed)._"
      }

      setBusyPhase("llm")

      const envSection =
        "## Environmental Context (live SQLite cti_vault)\n\n" +
        (envBlock || "_No CVE/IOC rows returned for the snapshot._")

      const systemContent = [BARNEY_SYSTEM, envSection, vaultBlock].filter(Boolean).join("\n\n")

      const ollamaMessages: { role: string; content: string }[] = [
        { role: "system", content: systemContent },
      ]
      for (const m of thread) {
        ollamaMessages.push({ role: m.role, content: m.content })
      }

      const data = await invoke<unknown>("invoke_local_llm", {
        payload: {
          messages: ollamaMessages,
          model: modelTag,
          ollamaHost,
        },
      })

      const content = sanitizeBarneyAssistantText(extractLlmContent(data))
      setMessages((p) => [
        ...p,
        {
          id: newMessageId(),
          role: "assistant",
          content: content || "(empty model reply)",
        },
      ])
      onScriptActivity?.()
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e)
      setMessages((p) => [
        ...p,
        {
          id: newMessageId(),
          role: "assistant",
          content: `**Error**\n\n\`${err}\``,
        },
      ])
    } finally {
      setBusy(false)
      setBusyPhase("idle")
    }
  }, [baseUrl, busy, draft, includeVaultData, messages, model, onScriptActivity])

  return (
    <div
      className={cn(
        "flex min-h-0 flex-1 flex-col overflow-hidden",
        center
          ? "rounded-none border-0 bg-transparent"
          : "rounded-xl border border-white/10 bg-black/25",
        className
      )}
    >
      <div
        className={cn(
          "flex shrink-0 flex-col gap-2 border-b border-white/10 bg-[oklch(0.09_0.01_260)] px-3",
          center ? "py-1.5" : "py-2.5"
        )}
      >
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h2 className={cn("font-semibold tracking-tight text-foreground", center ? "text-xs" : "text-sm")}>
              Barney
            </h2>
            <p className={cn("text-muted-foreground", center ? "text-[9px]" : "text-[10px]")}>
              {AGENT_TAGLINE}{" "}
              <span className="text-zinc-600">
                · <span className="font-mono">invoke_local_llm</span>
                {includeVaultData ? (
                  <>
                    {" "}
                    · <span className="font-mono">semantic_threat_search</span>
                  </>
                ) : null}
              </span>
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-8 border-white/15 bg-black/30 px-2 text-[11px]"
              disabled={busy}
              onClick={clearContext}
            >
              <Eraser className="mr-1 size-3.5" aria-hidden />
              Clear context
            </Button>
            <label className="flex cursor-pointer select-none items-center gap-2 rounded-md border border-white/10 bg-black/25 px-2 py-1 text-[11px] text-muted-foreground">
              <input
                type="checkbox"
                className="size-3.5 rounded border-white/20 bg-zinc-900 accent-cyan-500"
                checked={includeVaultData}
                disabled={busy}
                onChange={(e) => setIncludeVaultData(e.target.checked)}
              />
              <span className={cn("font-medium", includeVaultData && "text-cyan-200")}>
                Include vault data
              </span>
            </label>
          </div>
        </div>
      </div>

      <ScrollArea className="min-h-0 flex-1" ref={scrollRootRef}>
        <div className={cn("space-y-3 px-3 py-3", center && "px-4 sm:px-6")}>
          {messages.length === 0 ? (
            <p className="text-center text-xs text-muted-foreground">
              Each send loads <span className="font-medium text-foreground">Environmental Context</span> (top CVEs +
              IOCs from cti_vault) into the LLM. Turn on{" "}
              <span className="font-medium text-foreground">Include vault data</span> to add semantic search hits.
              Watch-floor nudges run when <span className="font-medium text-foreground">layout=center</span>. All
              traffic stays on Tauri IPC.
            </p>
          ) : null}
          {messages.map((m) => (
            <div
              key={m.id}
              className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
            >
              <div
                className={cn(
                  "rounded-2xl border px-3 py-2 text-sm leading-relaxed shadow-sm",
                  center
                    ? m.role === "user"
                      ? "max-w-[min(100%,42rem)]"
                      : "max-w-[min(100%,min(56rem,92vw))]"
                    : "max-w-[min(100%,28rem)]",
                  m.role === "user"
                    ? "border-cyan-500/25 bg-cyan-950/40 text-foreground"
                    : "border-white/10 bg-zinc-950/80 text-zinc-100"
                )}
              >
                {m.role === "assistant" ? (
                  <div className="overflow-x-auto font-sans text-[13px] leading-relaxed tracking-tight text-zinc-100">
                    <pre className="whitespace-pre-wrap break-words font-sans">{m.content}</pre>
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap break-words">{m.content}</p>
                )}
              </div>
            </div>
          ))}
          {busy ? (
            <div className="flex justify-start">
              <div className="flex items-center gap-2 rounded-2xl border border-white/10 bg-zinc-950/80 px-3 py-2 text-xs text-muted-foreground">
                <Loader2 className="size-3.5 animate-spin" aria-hidden />
                {busyPhase === "vault"
                  ? "Running semantic vault search…"
                  : busyPhase === "context"
                    ? "Loading Environmental Context from cti_vault…"
                    : "Barney is calling the local LLM…"}
              </div>
            </div>
          ) : null}
        </div>
      </ScrollArea>

      <div className="shrink-0 border-t border-white/10 bg-[oklch(0.08_0.01_260)] p-3">
        <Textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          disabled={busy}
          placeholder="Message Barney (Shift+Enter for newline)…"
          className="min-h-[72px] resize-none border-white/10 bg-black/35 text-sm"
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault()
              void send()
            }
          }}
        />
        <div className="mt-2 flex items-center justify-between gap-2">
          <span className="truncate font-mono text-[10px] text-muted-foreground">
            {includeVaultData ? "LLM + semantic_threat_search" : "invoke_local_llm"} · {model} @ {baseUrl}
          </span>
          <Button
            type="button"
            size="sm"
            disabled={busy || !draft.trim()}
            className="h-9 gap-1.5 bg-cyan-600 text-black hover:bg-cyan-500"
            onClick={() => void send()}
          >
            {busy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Send className="size-3.5" aria-hidden />}
            Send
          </Button>
        </div>
      </div>
    </div>
  )
}
