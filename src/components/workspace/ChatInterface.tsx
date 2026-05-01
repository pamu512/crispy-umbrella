"use client"

import * as React from "react"
import { motion, AnimatePresence } from "framer-motion"
import { invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import { readTextFile } from "@tauri-apps/plugin-fs"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { useOllamaSettings } from "@/components/OllamaSettingsProvider"
import { ollamaChatUrl } from "@/lib/ollama-config"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  MessageBlockView,
  type MessageBlock,
} from "@/components/workspace/MessageRenderers"
import { buildGenericRunPreview, buildIntelxComposePreview } from "@/lib/cti-tools"
import { invokeRunProject } from "@/lib/run-project"
import { useScriptConsole } from "@/components/workspace/ScriptConsoleProvider"
import { Paperclip, Send, Square } from "lucide-react"
import { cn } from "@/lib/utils"

type OllamaRole = "user" | "assistant" | "system" | "tool"

interface OllamaApiMessage {
  role: OllamaRole
  content?: string
  name?: string
  tool_calls?: Array<{
    function: { name: string; arguments: string | Record<string, unknown> }
  }>
}

export interface ChatTurn {
  id: string
  role: "user" | "assistant"
  blocks: MessageBlock[]
}

function parseIntelxIntent(text: string): string | null {
  const t = text.trim()
  const m =
    t.match(/\b(?:run|start|execute)\s+intelx\s+(?:for\s+)?(\S+)\s*$/i) ||
    t.match(/\bintelx\s+(?:for\s+)?(\S+)\s*$/i)
  if (!m) return null
  return m[1].replace(/^["']|["']$/g, "")
}

function parseToolArgs(raw: string | Record<string, unknown>) {
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as Record<string, unknown>
    } catch {
      return {}
    }
  }
  return raw as Record<string, unknown>
}

/** Join a path under workspace; rejects `..` segments. */
function resolveWorkspaceRelative(
  workspacePath: string,
  relativePath: string
): string | null {
  const root = workspacePath.replace(/\/+$/, "")
  const rel = relativePath.replace(/^\/+/, "").replace(/\\/g, "/")
  const segments = rel.split("/").filter(Boolean)
  if (segments.some((s) => s === "..")) return null
  return `${root}/${segments.join("/")}`
}

/** Stable-unique chat turn / confirm ids (same-ms `Date.now()` caused duplicate React keys). */
function turnUid(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`
}

export function ChatInterface({
  investigating,
  onInvestigatingChange,
  onScriptActivity,
}: {
  investigating: boolean
  onInvestigatingChange: (v: boolean) => void
  onScriptActivity: () => void
}) {
  const { workspacePath, scriptsRoot } = useWorkspace()
  const { baseUrl, model, ready: ollamaReady } = useOllamaSettings()
  const { snapshotText } = useScriptConsole()
  const [turns, setTurns] = React.useState<ChatTurn[]>([])
  const [draft, setDraft] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [confirmedIds, setConfirmedIds] = React.useState<Set<string>>(() => new Set())
  const abortRef = React.useRef<AbortController | null>(null)
  const scrollRef = React.useRef<HTMLDivElement>(null)

  const apiMessagesRef = React.useRef<OllamaApiMessage[]>([
    {
      role: "system",
      content:
        "You are an elite CTI analyst copilot. Use tools. Always use run_project when execution is needed; the operator must confirm in the UI before it runs. " +
        "After IntelX / leak-style runs (especially when no credential patterns matched), always end with a short **Recommended follow-ups** section: concrete next checks (PII columns, phones, IPs, alternate queries). Prefer **in-app** actions: call read_workspace_text on paths logged under the workspace (e.g. Intelx_Crawler/final_report/*.csv) to preview headers and rows, read_console_output for more log context, query_db when vault tables apply, and emit one or more run_project tool_calls for follow-up IntelX or other projects so the operator gets confirm cards—do not only paste shell grep/cat unless the file is too large or unreadable. " +
        "After scripts or Docker jobs finish, use read_console_output to read buffered stdout/stderr from the Console (filter by projectName e.g. Intelx_Crawler). " +
        "Interpret IntelX lines: search result UUID, record counts, CSV/report paths, exit status. Note: docker compose often prefixes harmless container lifecycle lines with ERROR: even on success. " +
        "When CVE_Project_NVD finishes successfully, the app upserts into cti_vault.cve_data (cve_id PK, severity_score, published_date, updated_at, metadata JSON). IOC crawler fills ioc_news then ioc_records; ASM fills asm_assets (asset_target PK, asset_type, last_scan_at, status, metadata). query_db is SELECT-only. " +
        "ASM-fetch-main runs export_asm_to_cti_vault.py when present to fill asm_assets from Postgres (see ASM README); CSV fallback if DB is offline. " +
        "Social_MediaV2 requires socialMediaTarget (and optional socialMediaStartDate, socialMediaEndDate, socialMediaNumPerPlatform); after success CSV rows upsert into cti_vault.social_media_results. " +
        "Phishing_and_Social_Media_All-in-one runs brand_scout.py: pass phishingScanType PS|SMS|ALL, phishingStartDate, phishingEndDate; for PS/ALL pass phishingDomains; for SMS/ALL pass phishingKeywords.",
    },
  ])

  React.useEffect(() => {
    onInvestigatingChange(loading)
  }, [loading, onInvestigatingChange])

  React.useEffect(() => {
    const el = scrollRef.current?.querySelector("[data-radix-scroll-area-viewport]")
    if (el) el.scrollTop = el.scrollHeight
  }, [turns, loading])

  const runOllamaOnce = React.useCallback(
    async (messages: OllamaApiMessage[], signal: AbortSignal) => {
      const url = ollamaChatUrl(baseUrl)
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal,
        body: JSON.stringify({
          model,
          messages,
          tools: [
            {
              type: "function",
              function: {
                name: "query_db",
                description: "Query cti_vault.db (SELECT only).",
                parameters: {
                  type: "object",
                  properties: { query: { type: "string" } },
                  required: ["query"],
                },
              },
            },
            {
              type: "function",
              function: {
                name: "read_shared_utils",
                description: "Read a file under shared_utils/.",
                parameters: {
                  type: "object",
                  properties: { filename: { type: "string" } },
                  required: ["filename"],
                },
              },
            },
            {
              type: "function",
              function: {
                name: "read_console_output",
                description:
                  "Read recent lines from the app Console (script/docker stdout and stderr). Use after tool runs to analyze IntelX results, errors, and exit codes.",
                parameters: {
                  type: "object",
                  properties: {
                    projectName: {
                      type: "string",
                      description: "Optional: only lines tagged with this project (e.g. Intelx_Crawler).",
                    },
                    maxLines: {
                      type: "integer",
                      description: "Max lines from the end of the buffer (default 200, max 500).",
                    },
                  },
                },
              },
            },
            {
              type: "function",
              function: {
                name: "read_workspace_text",
                description:
                  "Read a UTF-8 text file under the current workspace (CSV, log, report). Use after IntelX to preview final_report or csv_output paths from logs; paths are relative to workspace root. Large files are truncated.",
                parameters: {
                  type: "object",
                  properties: {
                    relativePath: {
                      type: "string",
                      description:
                        "Path under workspace, e.g. Intelx_Crawler/final_report/anoop_pamu@gmail_com_2000-01-01_to_2099-12-31.csv",
                    },
                    maxChars: {
                      type: "integer",
                      description: "Max characters to return (default 120000, max 400000).",
                    },
                  },
                  required: ["relativePath"],
                },
              },
            },
            {
              type: "function",
              function: {
                name: "run_project",
                description:
                  "Run a workspace project (UI confirmation). Use for initial and follow-up IntelX windows (adjusted intelxQuery/dates/limit), Brand Scout, Social Media, etc. You may emit multiple run_project calls in one assistant turn so the operator can confirm a short chain of steps.",
              parameters: {
                type: "object",
                properties: {
                  projectName: { type: "string" },
                  scriptType: { type: "string" },
                  intelxQuery: { type: "string" },
                  intelxStartDate: { type: "string" },
                  intelxEndDate: { type: "string" },
                  intelxSearchLimit: { type: "string" },
                  socialMediaTarget: { type: "string" },
                  socialMediaStartDate: { type: "string" },
                  socialMediaEndDate: { type: "string" },
                  socialMediaNumPerPlatform: { type: "string" },
                  phishingScanType: { type: "string" },
                  phishingDomains: { type: "string" },
                  phishingKeywords: { type: "string" },
                  phishingStartDate: { type: "string" },
                  phishingEndDate: { type: "string" },
                },
                required: ["projectName", "scriptType"],
              },
              },
            },
          ],
          stream: false,
        }),
      })
      const raw = await res.text()
      if (!res.ok) {
        let detail = raw.slice(0, 400)
        try {
          const j = JSON.parse(raw) as { error?: string }
          if (typeof j.error === "string") detail = j.error
        } catch {
          /* keep text */
        }
        if (res.status === 404) {
          throw new Error(
            `Ollama 404: ${detail}. Usually the model tag is wrong or not installed (ollama pull ${model}). Use the Ollama button in the header to change base URL or model.`
          )
        }
        throw new Error(`Ollama HTTP ${res.status}: ${detail}`)
      }
      return JSON.parse(raw) as { message: OllamaApiMessage }
    },
    [baseUrl, model]
  )

  const appendTurn = (t: ChatTurn) => setTurns((prev) => [...prev, t])

  React.useEffect(() => {
    let unlisten: (() => void) | undefined
    void listen<{ prompt?: string }>("copilot_prefill", (event) => {
      const p = event.payload?.prompt
      if (typeof p === "string" && p.trim()) {
        setDraft(p.trim())
        setTurns((prev) => [
          ...prev,
          {
            id: turnUid("t"),
            role: "assistant",
            blocks: [
              {
                type: "text",
                content:
                  "Brand Scout finished. The composer below is prefilled with an analysis request — review the Console log, then send to run the agent over your workspace.",
              },
            ],
          },
        ])
      }
    }).then((fn) => {
      unlisten = fn
    })
    return () => {
      unlisten?.()
    }
  }, [])

  const continueAfterTools = React.useCallback(
    async (signal: AbortSignal) => {
      let guard = 0
      while (guard++ < 8 && !signal.aborted) {
        const data = await runOllamaOnce(apiMessagesRef.current, signal)
        const msg = data.message
        if (!msg.tool_calls?.length) {
          const text = msg.content ?? ""
          apiMessagesRef.current.push({ role: "assistant", content: text })
          const blocks: MessageBlock[] = [{ type: "text", content: text }]
          appendTurn({ id: turnUid("t"), role: "assistant", blocks })
          return
        }

        apiMessagesRef.current.push(msg)

        const confirmBlocks: MessageBlock[] = []
        let needConfirm = false

        for (let idx = 0; idx < msg.tool_calls.length; idx++) {
          const call = msg.tool_calls[idx]
          const name = call.function.name
          const args = parseToolArgs(call.function.arguments)
          if (name === "run_project") {
            needConfirm = true
            const id = turnUid(`c_${idx}`)
            const pn = String(args.projectName ?? "")
            const st = String(args.scriptType ?? "")
            const iq = args.intelxQuery != null ? String(args.intelxQuery).trim() : ""
            const pick = (k1: string, k2: string) => {
              const v = args[k1] ?? args[k2]
              return v != null && String(v).trim() ? String(v).trim() : null
            }
            const isd = pick("intelxStartDate", "intelx_start_date")
            const ied = pick("intelxEndDate", "intelx_end_date")
            const isl = pick("intelxSearchLimit", "intelx_search_limit")
            const smt = pick("socialMediaTarget", "social_media_target")
            const sms = pick("socialMediaStartDate", "social_media_start_date")
            const sme = pick("socialMediaEndDate", "social_media_end_date")
            const smn = pick("socialMediaNumPerPlatform", "social_media_num_per_platform")
            const phst = pick("phishingScanType", "phishing_scan_type")
            const phd = pick("phishingDomains", "phishing_domains")
            const phk = pick("phishingKeywords", "phishing_keywords")
            const phsd = pick("phishingStartDate", "phishing_start_date")
            const phed = pick("phishingEndDate", "phishing_end_date")
            confirmBlocks.push({
              type: "confirm_execution",
              id,
              summary: `Run ${pn}`,
              commandPreview:
                pn === "Intelx_Crawler" && iq
                  ? buildIntelxComposePreview(iq, {
                      startDate: isd,
                      endDate: ied,
                      searchLimit: isl,
                    })
                  : buildGenericRunPreview(pn, st),
              payload: {
                projectName: pn,
                scriptType: st,
                intelxQuery: iq.length ? iq : null,
                intelxStartDate: isd,
                intelxEndDate: ied,
                intelxSearchLimit: isl,
                socialMediaTarget: smt,
                socialMediaStartDate: sms,
                socialMediaEndDate: sme,
                socialMediaNumPerPlatform: smn,
                phishingScanType: phst,
                phishingDomains: phd,
                phishingKeywords: phk,
                phishingStartDate: phsd,
                phishingEndDate: phed,
              },
            })
            continue
          }
          if (name === "query_db") {
            const result = await invoke("query_db", {
              workspacePath,
              query: String(args.query ?? ""),
            }).catch((e) => String(e))
            apiMessagesRef.current.push({
              role: "tool",
              name: "query_db",
              content: JSON.stringify(result),
            })
          } else if (name === "read_shared_utils") {
            const path = `${workspacePath}/shared_utils/${String(args.filename ?? "")}`
            const text = await readTextFile(path).catch((e) => String(e))
            apiMessagesRef.current.push({
              role: "tool",
              name: "read_shared_utils",
              content: text,
            })
          } else if (name === "read_console_output") {
            const pn = args.projectName != null ? String(args.projectName).trim() : ""
            const rawMax = args.maxLines
            const maxLines =
              rawMax != null && Number.isFinite(Number(rawMax))
                ? Math.min(500, Math.max(1, Math.floor(Number(rawMax))))
                : 200
            const text = snapshotText({
              projectName: pn.length ? pn : null,
              maxLines,
            })
            apiMessagesRef.current.push({
              role: "tool",
              name: "read_console_output",
              content: text,
            })
          } else if (name === "read_workspace_text") {
            const rel = String(args.relativePath ?? "").trim()
            const resolved =
              workspacePath && rel.length ? resolveWorkspaceRelative(workspacePath, rel) : null
            if (!resolved) {
              apiMessagesRef.current.push({
                role: "tool",
                name: "read_workspace_text",
                content: JSON.stringify({
                  error: "Missing workspace, empty relativePath, or path escapes workspace (..).",
                }),
              })
            } else {
              const rawMc = args.maxChars
              const maxChars =
                rawMc != null && Number.isFinite(Number(rawMc))
                  ? Math.min(400_000, Math.max(4_000, Math.floor(Number(rawMc))))
                  : 120_000
              let body = await readTextFile(resolved).catch((e) => `ERROR: ${String(e)}`)
              if (body.length > maxChars) {
                body =
                  body.slice(0, maxChars) +
                  `\n...[truncated at ${maxChars} characters; narrow path or raise maxChars]`
              }
              apiMessagesRef.current.push({
                role: "tool",
                name: "read_workspace_text",
                content: body,
              })
            }
          }
        }

        if (needConfirm) {
          appendTurn({
            id: turnUid("t"),
            role: "assistant",
            blocks: [
              {
                type: "text",
                content: "The model requested execution. Confirm the exact command below.",
              },
              ...confirmBlocks,
            ],
          })
          return
        }
      }
    },
    [runOllamaOnce, workspacePath, snapshotText]
  )

  const handleSend = async () => {
    const text = draft.trim()
    if (!text || !workspacePath || loading) return
    if (!ollamaReady) {
      appendTurn({
        id: turnUid("t"),
        role: "assistant",
        blocks: [{ type: "text", content: "Ollama settings are still loading. Try again in a moment." }],
      })
      return
    }

    abortRef.current?.abort()
    abortRef.current = new AbortController()
    const signal = abortRef.current.signal

    setDraft("")
    appendTurn({ id: turnUid("u"), role: "user", blocks: [{ type: "text", content: text }] })
    apiMessagesRef.current.push({ role: "user", content: text })
    setLoading(true)

    try {
      const quick = parseIntelxIntent(text)
      if (quick) {
        const id = turnUid("c_quick")
        appendTurn({
          id: turnUid("t"),
          role: "assistant",
          blocks: [
            {
              type: "text",
              content: `Ready to run IntelX for \`${quick}\`.`,
            },
            {
              type: "confirm_execution",
              id,
              summary: "Run Intelx_Crawler (Docker Compose)",
              commandPreview: buildIntelxComposePreview(quick),
              payload: {
                projectName: "Intelx_Crawler",
                scriptType: "sh",
                intelxQuery: quick,
              },
            },
          ],
        })
        return
      }

      await continueAfterTools(signal)
    } catch (e) {
      if ((e as Error).name === "AbortError") return
      appendTurn({
        id: turnUid("t"),
        role: "assistant",
        blocks: [{ type: "text", content: `Error: ${String(e)}` }],
      })
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async (block: Extract<MessageBlock, { type: "confirm_execution" }>) => {
    const confirmId = block.id
    if (confirmedIds.has(confirmId) || !workspacePath) return
    setConfirmedIds((s) => new Set(s).add(confirmId))

    const {
      projectName,
      scriptType,
      intelxQuery,
      intelxStartDate,
      intelxEndDate,
      intelxSearchLimit,
      socialMediaTarget,
      socialMediaStartDate,
      socialMediaEndDate,
      socialMediaNumPerPlatform,
      phishingScanType,
      phishingDomains,
      phishingKeywords,
      phishingStartDate,
      phishingEndDate,
    } = block.payload
    appendTurn({
      id: turnUid("t"),
      role: "assistant",
      blocks: [
        {
          type: "script_run",
          project: projectName,
          status: "running",
          detail: "Tauri invoke…",
        },
      ],
    })

    try {
      if (projectName === "Intelx_Crawler") {
        const q = (intelxQuery ?? "").trim()
        if (!q) throw new Error("IntelX target (query) is missing from this confirmation.")
        await invokeRunProject(
          workspacePath,
          projectName,
          scriptType,
          {
            query: q,
            startDate: intelxStartDate ?? undefined,
            endDate: intelxEndDate ?? undefined,
            searchLimit: intelxSearchLimit ?? undefined,
          },
          null,
          null,
          null,
          { scriptsRoot: scriptsRoot ?? undefined }
        )
      } else if (projectName === "Social_MediaV2") {
        const t = (socialMediaTarget ?? "").trim()
        if (!t) throw new Error("Social Media V2 target is missing from this confirmation.")
        await invokeRunProject(
          workspacePath,
          projectName,
          scriptType,
          null,
          {
            target: t,
            startDate: socialMediaStartDate ?? undefined,
            endDate: socialMediaEndDate ?? undefined,
            numPerPlatform: socialMediaNumPerPlatform ?? undefined,
          },
          null,
          null,
          { scriptsRoot: scriptsRoot ?? undefined }
        )
      } else if (projectName === "Phishing_and_Social_Media_All-in-one") {
        const st = (phishingScanType ?? "").trim().toUpperCase()
        if (st !== "PS" && st !== "SMS" && st !== "ALL") {
          throw new Error("Brand Scout needs phishingScanType PS, SMS, or ALL.")
        }
        const sd = (phishingStartDate ?? "").trim()
        const ed = (phishingEndDate ?? "").trim()
        if (!sd || !ed) throw new Error("Brand Scout needs phishingStartDate and phishingEndDate.")
        await invokeRunProject(
          workspacePath,
          projectName,
          scriptType,
          null,
          null,
          {
            scanType: st as "PS" | "SMS" | "ALL",
            domains: (phishingDomains ?? "").trim() || undefined,
            keywords: (phishingKeywords ?? "").trim() || undefined,
            startDate: sd,
            endDate: ed,
          },
          null,
          { scriptsRoot: scriptsRoot ?? undefined }
        )
      } else {
        await invokeRunProject(workspacePath, projectName, scriptType, null, null, null, null, {
          scriptsRoot: scriptsRoot ?? undefined,
        })
      }
      onScriptActivity()
      appendTurn({
        id: turnUid("t"),
        role: "assistant",
        blocks: [
          {
            type: "script_run",
            project: projectName,
            status: "done",
            detail: "Spawned. Logs appear in the console drawer.",
          },
        ],
      })
      if (!confirmId.startsWith("c_quick_")) {
        apiMessagesRef.current.push({
          role: "tool",
          name: "run_project",
          content: JSON.stringify({ ok: true, project: projectName }),
        })
        setLoading(true)
        abortRef.current = new AbortController()
        await continueAfterTools(abortRef.current.signal)
      }
    } catch (e) {
      appendTurn({
        id: turnUid("t"),
        role: "assistant",
        blocks: [
          {
            type: "script_run",
            project: projectName,
            status: "error",
            detail: String(e),
          },
        ],
      })
    } finally {
      setLoading(false)
    }
  }

  const stop = () => {
    abortRef.current?.abort()
    setLoading(false)
  }

  return (
    <motion.div
      layout
      className={cn(
        "flex min-h-0 flex-1 flex-col rounded-xl border transition-colors duration-500",
        investigating
          ? "border-cyan-500/25 shadow-[0_0_48px_-16px_rgba(34,211,238,0.22)]"
          : "border-white/10"
      )}
    >
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl">
        <div className="border-b border-white/10 px-4 py-2.5">
          <p className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
            Investigation thread
          </p>
          <p className="text-xs text-muted-foreground/80">
            Example:{" "}
            <span className="font-mono text-foreground/70">Run IntelX for victim@example.com</span>
          </p>
        </div>

        <ScrollArea className="min-h-0 flex-1 px-3 py-3" ref={scrollRef}>
          <div className="space-y-4 pb-4">
            <AnimatePresence initial={false}>
              {turns.map((turn) => (
                <motion.div
                  key={turn.id}
                  layout
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn("flex", turn.role === "user" ? "justify-end" : "justify-start")}
                >
                  <div
                    className={cn(
                      "max-w-[min(100%,52rem)] rounded-2xl border px-3.5 py-2.5 shadow-sm",
                      turn.role === "user"
                        ? "border-cyan-500/20 bg-cyan-950/35"
                        : "border-white/10 bg-black/35"
                    )}
                  >
                    {turn.blocks.map((b, i) => {
                      if (b.type === "confirm_execution" && confirmedIds.has(b.id)) {
                        return (
                          <p key={i} className="text-xs text-muted-foreground">
                            Confirmed.
                          </p>
                        )
                      }
                      return (
                        <MessageBlockView
                          key={i}
                          block={b}
                          onConfirmExecution={
                            b.type === "confirm_execution"
                              ? (blk) => void handleConfirm(blk)
                              : undefined
                          }
                        />
                      )
                    })}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            {loading ? (
              <p className="font-mono text-[11px] text-muted-foreground animate-pulse">
                Agent working…
              </p>
            ) : null}
          </div>
        </ScrollArea>

        <div className="border-t border-white/10 p-3">
          <Textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={loading}
            placeholder="Direct the agent… (Shift+Enter newline)"
            className="min-h-[72px] resize-none border-white/10 bg-black/30 font-sans text-sm"
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault()
                void handleSend()
              }
            }}
          />
          <div className="mt-2 flex items-center justify-end gap-1.5">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-9 text-muted-foreground"
              title="Attach (soon)"
              onClick={() => {}}
            >
              <Paperclip className="size-4" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-9 text-muted-foreground"
              title="Stop generation"
              disabled={!loading}
              onClick={stop}
            >
              <Square className="size-4" />
            </Button>
            <Button
              type="button"
              size="sm"
              className="h-9 gap-1.5 bg-cyan-600 text-black hover:bg-cyan-500"
              disabled={loading || !draft.trim()}
              onClick={() => void handleSend()}
            >
              <Send className="size-3.5" />
              Run
            </Button>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
