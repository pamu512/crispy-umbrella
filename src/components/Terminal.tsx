"use client"

import React, { useEffect, useRef, useState } from "react"
import { listen } from "@tauri-apps/api/event"
import { ScrollArea } from "./ui/scroll-area"

interface LogPayload {
  project: string
  message: string
}

interface LogEntry extends LogPayload {
  id: number
  timestamp: string
}

export function Terminal() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const scrollRef = useRef<HTMLDivElement>(null)
  /** Monotonic keys so batched script-log lines never share `key` (Date.now()+random can collide). */
  const lineIdSeq = useRef(0)

  useEffect(() => {
    let unlisten: () => void

    async function setupListener() {
      unlisten = await listen<LogPayload>("script-log", (event) => {
        setLogs(prev => {
          const newLogs = [...prev, {
            ...event.payload,
            id: ++lineIdSeq.current,
            timestamp: new Date().toLocaleTimeString()
          }]
          if (newLogs.length > 200) newLogs.shift() // keep last 200 logs
          return newLogs
        })
      })
    }

    setupListener()

    return () => {
      if (unlisten) unlisten()
    }
  }, [])

  useEffect(() => {
    // Auto-scroll to bottom
    if (scrollRef.current) {
      const el = scrollRef.current.querySelector('[data-radix-scroll-area-viewport]')
      if (el) {
        el.scrollTop = el.scrollHeight
      }
    }
  }, [logs])

  return (
    <div className="fixed bottom-0 left-0 right-0 h-48 bg-zinc-950 border-t border-zinc-800 z-50 flex flex-col font-mono text-xs">
      <div className="flex items-center px-4 py-1 bg-zinc-900 border-b border-zinc-800">
        <span className="text-zinc-400 font-semibold tracking-wider">TERMINAL</span>
        <button 
           className="ml-auto text-zinc-500 hover:text-zinc-300"
           onClick={() => setLogs([])}
        >
          Clear
        </button>
      </div>
      <ScrollArea className="flex-1 p-4" ref={scrollRef}>
        {logs.map(log => (
          <div key={log.id} className="flex gap-3 text-zinc-300 mb-1 leading-tight">
            <span className="text-zinc-600 shrink-0">{log.timestamp}</span>
            <span className="text-emerald-500 font-bold shrink-0">[{log.project}]</span>
            <span className={`break-all ${log.message.startsWith("ERROR:") ? "text-red-400" : ""}`}>
              {log.message}
            </span>
          </div>
        ))}
        {logs.length === 0 && (
          <div className="text-zinc-600 italic">Waiting for script execution logs...</div>
        )}
      </ScrollArea>
    </div>
  )
}
