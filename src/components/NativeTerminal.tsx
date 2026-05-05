"use client"

import * as React from "react"
import { listen, type UnlistenFn } from "@tauri-apps/api/event"

import { cn } from "@/lib/utils"

type AppLogPayload = {
  level: string
  target: string
  message: string
  timestamp: string
}

type LineEntry = AppLogPayload & { id: number }

const MAX_LINES = 800

function levelClass(level: string): string {
  const u = level.toUpperCase()
  if (u === "ERROR") return "text-red-400"
  if (u === "WARN") return "text-amber-400"
  if (u === "INFO") return "text-emerald-400"
  if (u === "DEBUG") return "text-zinc-500"
  if (u === "TRACE") return "text-zinc-600"
  return "text-emerald-300"
}

/** Heuristic styling for ingestion / connectivity lines in host logs. */
function messageClass(message: string): string {
  const m = message.toUpperCase()
  if (m.includes("CONNECTION REFUSED") || m.includes("UNAVAILABLE") || m.includes("FAILED TO")) {
    return "text-red-300"
  }
  if (m.includes("INGESTED") || m.includes("INGEST ") || m.includes("INGEST:")) {
    return "text-cyan-200"
  }
  if (m.includes("COMPLETE") || m.includes("SUCCESS") || m.includes("OK")) {
    return "text-emerald-200"
  }
  return "text-zinc-200"
}

/**
 * Subscribes to the Tauri **`app-log`** channel (see `logging::init_app_log_forwarder` in Rust).
 * Renders host log lines in a monospaced, scrollable panel—suitable for ingestion progress,
 * connection errors, and other backend diagnostics.
 */
export function NativeTerminal({
  className,
  compact = false,
  title = "Native log terminal",
}: {
  className?: string
  /** Shorter panel for sidebars. */
  compact?: boolean
  /** Header label. */
  title?: string
}) {
  const [lines, setLines] = React.useState<LineEntry[]>([])
  const idSeq = React.useRef(0)
  const viewportRef = React.useRef<HTMLDivElement>(null)

  React.useEffect(() => {
    let unlisten: UnlistenFn | undefined

    void listen<AppLogPayload>("app-log", (event) => {
      const p = event.payload
      setLines((prev) => {
        const next: LineEntry[] = [
          ...prev,
          {
            ...p,
            id: ++idSeq.current,
          },
        ]
        if (next.length > MAX_LINES) {
          return next.slice(-MAX_LINES)
        }
        return next
      })
    }).then((fn) => {
      unlisten = fn
    })

    return () => {
      void unlisten?.()
    }
  }, [])

  React.useLayoutEffect(() => {
    const el = viewportRef.current
    if (el) {
      el.scrollTop = el.scrollHeight
    }
  }, [lines])

  return (
    <div
      className={cn(
        "flex min-h-0 flex-col overflow-hidden border border-zinc-800 bg-black font-mono text-zinc-200 shadow-inner",
        compact ? "max-h-40 text-[10px] leading-tight" : "h-full min-h-[10rem] text-[11px] leading-snug sm:text-xs",
        className
      )}
    >
      <div className="flex shrink-0 items-center gap-2 border-b border-zinc-800 bg-zinc-950 px-2 py-1 sm:px-3 sm:py-1.5">
        <span className="truncate font-semibold uppercase tracking-widest text-zinc-500">{title}</span>
        <span className="shrink-0 rounded border border-zinc-800 px-1 py-px text-[9px] font-normal normal-case tracking-normal text-zinc-600">
          app-log
        </span>
        <button
          type="button"
          className="ml-auto shrink-0 rounded px-2 py-0.5 text-[10px] uppercase tracking-wide text-zinc-500 hover:bg-zinc-900 hover:text-zinc-300"
          onClick={() => setLines([])}
        >
          Clear
        </button>
      </div>
      <div
        ref={viewportRef}
        className="min-h-0 flex-1 overflow-y-auto overflow-x-auto whitespace-pre-wrap break-all px-2 py-2 sm:px-3"
        role="log"
        aria-live="polite"
        aria-relevant="additions"
      >
        {lines.length === 0 ? (
          <div className="italic text-zinc-600">Listening for host events (ingestion, vault, schedulers)…</div>
        ) : (
          lines.map((log) => (
            <div key={log.id} className="mb-1 border-b border-zinc-900/80 pb-1 last:border-0">
              <div className="flex flex-wrap gap-x-2 gap-y-0.5">
                <span className="shrink-0 text-zinc-600">{log.timestamp}</span>
                <span className={`shrink-0 font-bold ${levelClass(log.level)}`}>[{log.level}]</span>
                <span className="shrink-0 text-cyan-900">{log.target}</span>
              </div>
              <div className={cn("mt-0.5 pl-0 sm:pl-0", messageClass(log.message))}>{log.message}</div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
