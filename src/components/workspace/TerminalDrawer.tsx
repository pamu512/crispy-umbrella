"use client"

import * as React from "react"
import { AnimatePresence, motion } from "framer-motion"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { ChevronDown, Trash2 } from "lucide-react"
import { useScriptConsole } from "@/components/workspace/ScriptConsoleProvider"

export function TerminalDrawer({
  forcedOpen,
  onForcedOpenChange,
}: {
  forcedOpen: boolean
  onForcedOpenChange: (v: boolean) => void
}) {
  const { lines, clearLines } = useScriptConsole()
  const [dismissed, setDismissed] = React.useState(false)
  const scrollRef = React.useRef<HTMLDivElement>(null)
  const prevLen = React.useRef(0)

  React.useEffect(() => {
    if (lines.length > prevLen.current) setDismissed(false)
    prevLen.current = lines.length
  }, [lines.length])

  React.useEffect(() => {
    const el = scrollRef.current?.querySelector("[data-radix-scroll-area-viewport]")
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  const visible = forcedOpen || (lines.length > 0 && !dismissed)

  return (
    <>
      <AnimatePresence>
        {visible ? (
          <motion.div
            key="term"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "min(38vh, 320px)", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ type: "spring", stiffness: 380, damping: 32 }}
            className="fixed bottom-0 left-0 right-0 z-50 flex flex-col overflow-hidden border-t border-white/10 bg-zinc-950/95 font-mono text-[11px] backdrop-blur-md"
          >
            <div className="flex h-9 shrink-0 items-center border-b border-white/10 px-3">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Console
              </span>
              <span className="ml-3 font-mono text-[9px] text-zinc-500">{lines.length} lines</span>
              <div className="ml-auto flex items-center gap-1">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-[10px] text-muted-foreground"
                  onClick={() => clearLines()}
                >
                  <Trash2 className="mr-1 size-3" />
                  Clear
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={() => {
                    setDismissed(true)
                    onForcedOpenChange(false)
                  }}
                >
                  <ChevronDown className="size-4" />
                </Button>
              </div>
            </div>
            <ScrollArea className="min-h-0 flex-1 px-3 py-2" ref={scrollRef}>
              {lines.map((log) => (
                <div key={log.id} className="mb-1 flex gap-2 leading-tight text-zinc-300">
                  <span className="shrink-0 text-zinc-600">{log.timestamp}</span>
                  <span className="shrink-0 text-emerald-500/90">[{log.project}]</span>
                  <span
                    className={cn(
                      "break-all",
                      log.message.startsWith("ERROR:") && "text-red-400"
                    )}
                  >
                    {log.message}
                  </span>
                </div>
              ))}
              {!lines.length ? (
                <p className="text-zinc-600">Idle — logs appear when a tool runs.</p>
              ) : null}
            </ScrollArea>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {!visible && lines.length > 0 ? (
          <motion.button
            key="fab"
            type="button"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            className="fixed bottom-4 right-4 z-40 rounded-full border border-cyan-500/30 bg-zinc-950/90 px-4 py-2 font-mono text-[11px] text-cyan-200 shadow-lg backdrop-blur-md"
            onClick={() => {
              setDismissed(false)
              onForcedOpenChange(true)
            }}
          >
            Console · {lines.length} lines
          </motion.button>
        ) : null}
      </AnimatePresence>
    </>
  )
}
