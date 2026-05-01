"use client"

import React, { useState, useRef, useEffect } from "react"
import { invoke } from "@tauri-apps/api/core"
import { readTextFile } from "@tauri-apps/plugin-fs"
import { useWorkspace } from "./WorkspaceProvider"
import { Input } from "./ui/input"
import { Button } from "./ui/button"
import { ScrollArea } from "./ui/scroll-area"

interface Message {
  role: "user" | "assistant" | "tool"
  content: string
  name?: string
}

export function AICopilot() {
  const { workspacePath } = useWorkspace()
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      const el = scrollRef.current.querySelector('[data-radix-scroll-area-viewport]')
      if (el) el.scrollTop = el.scrollHeight
    }
  }, [messages])

  const appendMessage = (msg: Message) => setMessages(prev => [...prev, msg])

  const callOllama = async (msgs: Message[]) => {
    const tools = [
      {
        type: "function",
        function: {
          name: "query_db",
          description: "Query the local cti_vault.db SQLite database to find intel.",
          parameters: {
            type: "object",
            properties: {
              query: { type: "string", description: "The SQL SELECT query" }
            },
            required: ["query"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "read_shared_utils",
          description: "Read a file from the shared_utils folder to understand logic.",
          parameters: {
            type: "object",
            properties: {
              filename: { type: "string", description: "The filename in shared_utils, e.g. README.md" }
            },
            required: ["filename"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "run_feature",
          description:
            "Run a CTI feature by id. Scripts resolve from the app bundle; data writes to AppData. Do not invent absolute paths—only featureName plus optional fields such as scriptType, intelxQuery, socialMediaTarget, phishingScanType, rumarkDomains, etc.",
          parameters: {
            type: "object",
            properties: {
              featureName: {
                type: "string",
                description:
                  "One of: Intelx_Crawler, CVE_Project_NVD, ASM-fetch-main, Ransomware_live_event_victim, Phishing_and_Social_Media_All-in-one, Social_MediaV2, IOCs-crawler-main, Compromised_user_Mac",
              },
              scriptType: { type: "string", description: "Usually 'python' or 'sh' (default python)." },
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
              rumarkDomains: { type: "string" },
              rumarkCookie: { type: "string" },
            },
            required: ["featureName"],
          },
        },
      },
    ]

    try {
      const res = await fetch("http://localhost:11434/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "qwen2.5:32b", // or llama3.1
          messages: [
            {
              role: "system",
              content:
                "You are an Investigation Copilot. Use tools to answer questions. Paths are managed by the app: use run_feature with featureName (and optional arguments like intelxQuery)—do not guess absolute directories. Workflow: Discovery → read_shared_utils if needed → run_feature / query_db.",
            },
            ...msgs
          ],
          tools,
          stream: false
        })
      })

      if (!res.ok) {
         throw new Error("Failed to reach local Ollama on port 11434")
      }

      const data = await res.json()
      const msg = data.message

      if (msg.tool_calls && msg.tool_calls.length > 0) {
        appendMessage({ role: "assistant", content: `Calling tool: ${msg.tool_calls[0].function.name}` })
        
        let toolResult = ""
        for (const call of msg.tool_calls) {
          let args = call.function.arguments as Record<string, unknown> | string
          if (typeof args === "string") {
            try {
              args = JSON.parse(args) as Record<string, unknown>
            } catch {
              args = {}
            }
          }
          const a = args as Record<string, unknown>
          if (call.function.name === "query_db") {
             const result = await invoke("query_db", { workspacePath, query: String(a.query ?? "") }).catch(e => e)
             toolResult = JSON.stringify(result)
          } else if (call.function.name === "read_shared_utils") {
             const path = `${workspacePath}/shared_utils/${String(a.filename ?? "")}`
             toolResult = await readTextFile(path).catch(e => String(e))
          } else if (call.function.name === "run_feature") {
            const fname = String(a.featureName ?? a.projectName ?? "").trim()
            const args = { ...a } as Record<string, unknown>
            delete args.featureName
            delete args.projectName
            await invoke("run_feature_v2", {
              featureName: fname,
              arguments: args,
            }).catch((e) => String(e))
            toolResult = `Started feature ${fname}`
          }

          msgs.push(msg) // append the assistant's tool call request
          msgs.push({ role: "tool", name: call.function.name, content: toolResult })
        }
        
        // Recurse to let model generate final answer based on tool result
        await callOllama(msgs)
      } else {
        appendMessage({ role: "assistant", content: msg.content })
      }

    } catch (e) {
      appendMessage({ role: "assistant", content: `Error: ${String(e)}` })
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return
    
    const userMsg: Message = { role: "user", content: input }
    setInput("")
    setMessages(prev => [...prev, userMsg])
    setLoading(true)
    
    await callOllama([...messages, userMsg])
    setLoading(false)
  }

  return (
    <div className="flex flex-col h-full bg-zinc-950 text-sm">
      <div className="p-4 border-b border-border bg-zinc-900 font-semibold tracking-tight">
        Investigation Copilot
      </div>
      <ScrollArea className="flex-1 p-4" ref={scrollRef}>
        <div className="space-y-4">
          {messages.filter(m => m.role !== 'tool').map((m, i) => (
            <div key={i} className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
              <div className={`p-2 rounded-lg max-w-[90%] ${
                m.role === 'user' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-zinc-800 text-zinc-200'
              }`}>
                {m.content}
              </div>
            </div>
          ))}
          {loading && (
            <div className="text-zinc-500 italic text-xs animate-pulse">Copilot is thinking...</div>
          )}
          {messages.length === 0 && (
            <div className="text-zinc-500 italic text-center mt-10">
              Ask me to query the DB or run a script.
            </div>
          )}
        </div>
      </ScrollArea>
      <div className="p-4 border-t border-border bg-zinc-900">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <Input 
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={loading}
            placeholder="Ask Copilot..." 
            className="flex-1 bg-zinc-800 border-zinc-700 focus-visible:ring-1 focus-visible:ring-blue-500"
          />
          <Button type="submit" disabled={loading || !input.trim()} size="sm">
            Send
          </Button>
        </form>
      </div>
    </div>
  )
}
