"use client"

import * as React from "react"
import { motion } from "framer-motion"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { ProjectToolbox } from "@/components/workspace/ProjectToolbox"
import { LiveContextPanel } from "@/components/workspace/LiveContextPanel"
import { ChatInterface } from "@/components/workspace/ChatInterface"
import { TerminalDrawer } from "@/components/workspace/TerminalDrawer"
import { ScriptConsoleProvider } from "@/components/workspace/ScriptConsoleProvider"
import { CommandPalette } from "@/components/workspace/CommandPalette"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { FolderInput, Search, Settings, Terminal } from "lucide-react"
import { useOllamaSettings } from "@/components/OllamaSettingsProvider"
import { OllamaSettingsDialog } from "@/components/OllamaSettingsDialog"

export function InvestigationWorkspace() {
  const { workspacePath, selectWorkspace } = useWorkspace()
  const { model, baseUrl } = useOllamaSettings()
  const [settingsOpen, setSettingsOpen] = React.useState(false)
  const [leftCollapsed, setLeftCollapsed] = React.useState(false)
  const [paletteOpen, setPaletteOpen] = React.useState(false)
  const [forcedConsole, setForcedConsole] = React.useState(false)
  const [pulseToken, setPulseToken] = React.useState(0)
  const [investigating, setInvestigating] = React.useState(false)

  const bumpTelemetry = React.useCallback(() => {
    setPulseToken(Date.now())
  }, [])

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  return (
    <ScriptConsoleProvider onLog={bumpTelemetry}>
    <div className="flex h-screen flex-col bg-[oklch(0.07_0_0)] text-foreground">
      <motion.header
        layout
        className="glass-panel z-20 flex h-12 shrink-0 items-center gap-3 border-b border-white/10 px-3"
      >
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-sm font-semibold tracking-tight">Command Center</span>
          <Separator orientation="vertical" className="h-5 bg-white/15" />
          <span className="truncate font-mono text-[10px] text-muted-foreground" title={workspacePath ?? ""}>
            {workspacePath}
          </span>
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <span
            className="hidden max-w-[140px] truncate font-mono text-[9px] text-muted-foreground sm:inline"
            title={`${baseUrl} · ${model}`}
          >
            {model}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-8 border-white/15 bg-black/25 font-mono text-[10px]"
            onClick={() => setSettingsOpen(true)}
          >
            <Settings className="mr-1 size-3.5" />
            Ollama
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-8 border-white/15 bg-black/25 font-mono text-[10px]"
            onClick={() => setPaletteOpen(true)}
          >
            <Search className="mr-1 size-3.5" />
            Vault
            <kbd className="ml-1 rounded border border-white/20 bg-black/40 px-1 font-mono text-[9px]">
              ⌘K
            </kbd>
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-8 border-white/15 bg-black/25 font-mono text-[10px]"
            onClick={() => setForcedConsole(true)}
          >
            <Terminal className="mr-1 size-3.5" />
            Console
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 font-mono text-[10px] text-muted-foreground"
            onClick={() => void selectWorkspace()}
          >
            <FolderInput className="mr-1 size-3.5" />
            Workspace
          </Button>
        </div>
      </motion.header>

      <div className="relative flex min-h-0 flex-1">
        <ProjectToolbox
          collapsed={leftCollapsed}
          onCollapsedChange={setLeftCollapsed}
          onScriptActivity={bumpTelemetry}
        />

        <main className="flex min-w-0 flex-1 flex-col gap-2 px-3 py-2">
          <ChatInterface
            investigating={investigating}
            onInvestigatingChange={setInvestigating}
            onScriptActivity={bumpTelemetry}
          />
        </main>

        <LiveContextPanel pulseToken={pulseToken} />
      </div>

      <TerminalDrawer forcedOpen={forcedConsole} onForcedOpenChange={setForcedConsole} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
      <OllamaSettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
    </div>
    </ScriptConsoleProvider>
  )
}
