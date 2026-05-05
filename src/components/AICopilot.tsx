"use client"

import React, { useState, useRef, useEffect } from "react"
import { runCopilotInvestigationGraph } from "@/lib/copilot-langgraph"
import { useWorkspace } from "./WorkspaceProvider"
import { Input } from "./ui/input"
import { Button } from "./ui/button"
import { ScrollArea } from "./ui/scroll-area"

interface Message {
  role: "user" | "assistant"
  content: string
  /** Optional LangGraph trace (routing + tool steps). */
  trace?: string[]
}

export function AICopilot() {
  const { workspacePath } = useWorkspace()
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      const el = scrollRef.current.querySelector("[data-radix-scroll-area-viewport]")
      if (el) el.scrollTop = el.scrollHeight
    }
  }, [messages])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const q = input.trim()
    if (!q) return
    const wp = workspacePath
    if (!wp) {
      setMessages((prev) => [
        ...prev,
        { role: "user", content: q },
        {
          role: "assistant",
            content:
              "Select a workspace before using Barney for project-relative tools. The vault file uses the host canonical path (CTI_DB_PATH; default under OS app data, e.g. ~/Library/Application Support/com.pamu512.crispyumbrella/cti-app/).",
        },
      ])
      setInput("")
      return
    }

    const userMsg: Message = { role: "user", content: q }
    setInput("")
    setMessages((prev) => [...prev, userMsg])
    setLoading(true)

    try {
      const state = await runCopilotInvestigationGraph(wp, q)
      const trace = state.trace?.length ? state.trace : undefined
      const foot =
        trace && trace.length
          ? `\n\n---\n_Routing: ${state.route}_\n${trace.slice(-6).join("\n")}`
          : `\n\n---\n_Routing: ${state.route}_`
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: (state.finalAnswer || "(no answer)") + foot,
          trace,
        },
      ])
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `Error: ${String(err)}` },
      ])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-full flex-col bg-zinc-950 text-sm">
      <div className="border-border bg-zinc-900 p-4 font-semibold tracking-tight border-b">
        Barney · Investigation
        <p className="text-zinc-500 font-normal text-xs mt-1">
          CTI Command Center — LangGraph: understand → semantic / structured vault → synthesize (Ollama + Tauri).
        </p>
      </div>
      <ScrollArea className="flex-1 p-4" ref={scrollRef}>
        <div className="space-y-4">
          {messages.map((m, i) => (
            <div
              key={i}
              className={`flex flex-col ${m.role === "user" ? "items-end" : "items-start"}`}
            >
              <div
                className={`max-w-[90%] rounded-lg p-2 ${
                  m.role === "user" ? "bg-blue-600 text-white" : "bg-zinc-800 text-zinc-200"
                }`}
              >
                <div className="whitespace-pre-wrap">{m.content}</div>
              </div>
            </div>
          ))}
          {loading && (
            <div className="text-zinc-500 italic text-xs animate-pulse">Barney is thinking…</div>
          )}
          {messages.length === 0 && (
            <div className="text-zinc-500 italic text-center mt-10">
              Ask about threats in natural language (semantic) or paste exact IOCs / CVEs (structured).
            </div>
          )}
        </div>
      </ScrollArea>
      <div className="border-border bg-zinc-900 p-4 border-t">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            placeholder="Ask Barney…"
            className="flex-1 border-zinc-700 bg-zinc-800 focus-visible:ring-1 focus-visible:ring-blue-500"
          />
          <Button type="submit" disabled={loading || !input.trim()} size="sm">
            Send
          </Button>
        </form>
      </div>
    </div>
  )
}
