"use client"

import * as React from "react"
import { listen } from "@tauri-apps/api/event"

export interface ConsoleLogPayload {
  project: string
  message: string
}

export interface ConsoleLogLine extends ConsoleLogPayload {
  id: number
  timestamp: string
}

const MAX_STORED = 500

type ScriptConsoleContextValue = {
  lines: ConsoleLogLine[]
  clearLines: () => void
  /** Newest lines last; for Ollama tool calls. */
  snapshotText: (opts?: { projectName?: string | null; maxLines?: number }) => string
}

const ScriptConsoleContext = React.createContext<ScriptConsoleContextValue | null>(null)

export function ScriptConsoleProvider({
  children,
  onLog,
}: {
  children: React.ReactNode
  onLog?: () => void
}) {
  const [lines, setLines] = React.useState<ConsoleLogLine[]>([])
  /** Monotonic keys so batched script-log lines never share `key` (Date.now()+random can collide). */
  const lineIdSeq = React.useRef(0)

  React.useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | undefined
    void listen<ConsoleLogPayload>("script-log", (event) => {
      if (disposed) return
      setLines((prev) => {
        const next = [
          ...prev,
          {
            ...event.payload,
            id: ++lineIdSeq.current,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]
        if (next.length > MAX_STORED) next.splice(0, next.length - MAX_STORED)
        return next
      })
      onLog?.()
    }).then((u) => {
      if (disposed) {
        u()
        return
      }
      unlisten = u
    })
    return () => {
      disposed = true
      unlisten?.()
    }
  }, [onLog])

  const clearLines = React.useCallback(() => setLines([]), [])

  const snapshotText = React.useCallback(
    (opts?: { projectName?: string | null; maxLines?: number }) => {
      const cap = Math.min(MAX_STORED, Math.max(1, Math.floor(opts?.maxLines ?? 200)))
      let subset = lines
      const pn = opts?.projectName?.trim()
      if (pn) subset = lines.filter((l) => l.project === pn)
      const tail = subset.slice(-cap)
      if (!tail.length) {
        return "(Console buffer is empty — run a project from the toolbox or hub first, or widen filters.)"
      }
      return tail.map((l) => `${l.timestamp}\t[${l.project}]\t${l.message}`).join("\n")
    },
    [lines]
  )

  const value = React.useMemo(
    () => ({ lines, clearLines, snapshotText }),
    [lines, clearLines, snapshotText]
  )

  return <ScriptConsoleContext.Provider value={value}>{children}</ScriptConsoleContext.Provider>
}

export function useScriptConsole(): ScriptConsoleContextValue {
  const ctx = React.useContext(ScriptConsoleContext)
  if (!ctx) throw new Error("useScriptConsole must be used inside ScriptConsoleProvider")
  return ctx
}
