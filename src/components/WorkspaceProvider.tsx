"use client"

import React, { createContext, useContext, useEffect, useMemo, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import { open } from "@tauri-apps/plugin-dialog"
import { load } from "@tauri-apps/plugin-store"
import { ensureCtiWritableLayout } from "@/lib/initialization-service"

function normPath(p: string) {
  return p.replace(/\/+$/, "")
}

interface WorkspaceContextType {
  workspacePath: string | null
  setWorkspacePath: (path: string) => void
  selectWorkspace: () => Promise<void>
  writableRoot: string | null
  /** Only set when workspacePath === writableRoot (bundled scripts + AppData data). Otherwise null = legacy monorepo mode. */
  scriptsRoot: string | null
}

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined)

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [workspacePath, setWorkspacePathState] = useState<string | null>(null)
  const [writableRoot, setWritableRoot] = useState<string | null>(null)
  /** From `cti_bootstrap`; used only when data workspace is AppData home. */
  const [bundledScriptsRoot, setBundledScriptsRoot] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const scriptsRoot = useMemo(() => {
    if (!workspacePath || !writableRoot || !bundledScriptsRoot) return null
    if (normPath(workspacePath) !== normPath(writableRoot)) return null
    return bundledScriptsRoot
  }, [workspacePath, writableRoot, bundledScriptsRoot])

  useEffect(() => {
    async function loadWorkspace() {
      try {
        const boot = await ensureCtiWritableLayout()
        setWritableRoot(boot.writableRoot)
        setBundledScriptsRoot(boot.scriptsRoot ?? null)

        const store = await load("store.json", { autoSave: false } as any)
        const savedPath = await store.get<{ value: string }>("workspace_path")
        const path =
          savedPath && savedPath.value && savedPath.value.length > 0
            ? savedPath.value
            : boot.writableRoot
        setWorkspacePathState(path)
        await invoke("start_background_scheduler", { workspacePath: path })
        void invoke("bootstrap_all_feature_venvs").catch(() => {
          /* best-effort; bundle may omit some features */
        })
      } catch (err) {
        console.error("Failed to load workspace / bootstrap:", err)
      } finally {
        setLoading(false)
      }
    }
    loadWorkspace()
  }, [])

  const setWorkspacePath = async (path: string) => {
    try {
      const store = await load("store.json", { autoSave: false } as any)
      await store.set("workspace_path", { value: path })
      await store.save()
      setWorkspacePathState(path)
      await invoke("start_background_scheduler", { workspacePath: path })
    } catch (err) {
      console.error("Failed to save workspace path:", err)
    }
  }

  const selectWorkspace = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select CTI data folder (legacy All_Scripts monorepo or custom)",
      })
      if (selected && typeof selected === "string") {
        await setWorkspacePath(selected)
      }
    } catch (err) {
      console.error("Failed to select directory:", err)
    }
  }

  if (loading) return null

  if (!workspacePath) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-background">
        <div className="space-y-2 text-center text-sm text-muted-foreground">
          <p>Could not resolve a data workspace path.</p>
        </div>
      </div>
    )
  }

  return (
    <WorkspaceContext.Provider
      value={{
        workspacePath,
        setWorkspacePath,
        selectWorkspace,
        writableRoot,
        scriptsRoot,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  )
}

export function useWorkspace() {
  const context = useContext(WorkspaceContext)
  if (context === undefined) {
    throw new Error("useWorkspace must be used within a WorkspaceProvider")
  }
  return context
}
