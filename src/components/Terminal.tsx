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

const MAX_LINES = 500

function lineClassForLevel(level: string): string {
  const u = level.toUpperCase()
  if (u === "ERROR") return "text-red-400"
  if (u === "WARN") return "text-amber-400"
  if (u === "INFO") return "text-emerald-400"
  if (u === "DEBUG") return "text-zinc-500"
  if (u === "TRACE") return "text-zinc-600"
  return "text-emerald-300"
}

/**
 * Native **app-log** stream from the Tauri host (`logging::init_app_log_forwarder`).
 * Classic terminal styling: black field, monospace, green/amber/red by level.
 */
export function Terminal({ compact = false }: { compact?: boolean }) {
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
        "flex flex-col border border-zinc-800 bg-black font-mono text-emerald-400 shadow-inner",
        compact ? "h-36 text-[10px]" : "h-full min-h-[12rem] text-xs"
      )}
    >
      <div className="flex shrink-0 items-center border-b border-zinc-800 bg-zinc-950 px-2 py-1 sm:px-3 sm:py-1.5">
        <span className="font-semibold tracking-widest text-zinc-500">EVENT TERMINAL</span>
        <span className="ml-1.5 text-[9px] text-zinc-600 sm:ml-2 sm:text-[10px]">app-log</span>
        <button
          type="button"
          className="ml-auto rounded px-2 py-0.5 text-[10px] uppercase tracking-wide text-zinc-500 hover:bg-zinc-900 hover:text-zinc-300"
          onClick={() => setLines([])}
        >
          Clear
        </button>
      </div>
      <div
        ref={viewportRef}
        className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden px-3 py-2"
        role="log"
        aria-live="polite"
        aria-relevant="additions"
      >
        {lines.length === 0 ? (
          <div className="italic text-zinc-600">Waiting for Rust log events…</div>
        ) : (
          lines.map((log) => (
            <div key={log.id} className="mb-1 flex gap-2 leading-snug break-all">
              <span className="shrink-0 text-zinc-600">{log.timestamp}</span>
              <span className={`shrink-0 font-bold ${lineClassForLevel(log.level)}`}>
                [{log.level}]
              </span>
              <span className="shrink-0 text-cyan-700">{log.target}</span>
              <span className={lineClassForLevel(log.level)}>{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
