"use client"

import * as React from "react"
import { load } from "@tauri-apps/plugin-store"
import {
  OLLAMA_DEFAULT_BASE,
  OLLAMA_DEFAULT_MODEL,
  normalizeOllamaBaseUrl,
} from "@/lib/ollama-config"

const STORE_FILE = "store.json"
const KEY_BASE = "ollama_base_url"
const KEY_MODEL = "ollama_model"

type Ctx = {
  baseUrl: string
  model: string
  ready: boolean
  setBaseUrl: (v: string) => void
  setModel: (v: string) => void
  /** Persist explicit values (avoids stale React state when saving from a dialog). */
  persistSettings: (base: string, modelTag: string) => Promise<void>
  reload: () => Promise<void>
}

const OllamaSettingsContext = React.createContext<Ctx | null>(null)

export function OllamaSettingsProvider({ children }: { children: React.ReactNode }) {
  const [baseUrl, setBaseUrlState] = React.useState(OLLAMA_DEFAULT_BASE)
  const [model, setModelState] = React.useState(OLLAMA_DEFAULT_MODEL)
  const [ready, setReady] = React.useState(false)

  const reload = React.useCallback(async () => {
    try {
      const store = await load(STORE_FILE, { autoSave: false } as any)
      const b = await store.get<{ value: string }>(KEY_BASE)
      const m = await store.get<{ value: string }>(KEY_MODEL)
      if (b?.value?.trim()) setBaseUrlState(normalizeOllamaBaseUrl(b.value))
      else setBaseUrlState(OLLAMA_DEFAULT_BASE)
      if (m?.value?.trim()) setModelState(m.value.trim())
      else setModelState(OLLAMA_DEFAULT_MODEL)
    } catch {
      setBaseUrlState(OLLAMA_DEFAULT_BASE)
      setModelState(OLLAMA_DEFAULT_MODEL)
    } finally {
      setReady(true)
    }
  }, [])

  React.useEffect(() => {
    void reload()
  }, [reload])

  const setBaseUrl = React.useCallback((v: string) => {
    setBaseUrlState(normalizeOllamaBaseUrl(v || OLLAMA_DEFAULT_BASE))
  }, [])

  const setModel = React.useCallback((v: string) => {
    setModelState(v.trim() || OLLAMA_DEFAULT_MODEL)
  }, [])

  const persistSettings = React.useCallback(async (base: string, modelTag: string) => {
    const nb = normalizeOllamaBaseUrl(base || OLLAMA_DEFAULT_BASE)
    const nm = (modelTag || OLLAMA_DEFAULT_MODEL).trim() || OLLAMA_DEFAULT_MODEL
    const store = await load(STORE_FILE, { autoSave: false } as any)
    await store.set(KEY_BASE, { value: nb })
    await store.set(KEY_MODEL, { value: nm })
    await store.save()
    setBaseUrlState(nb)
    setModelState(nm)
  }, [])

  const value = React.useMemo(
    () =>
      ({
        baseUrl,
        model,
        ready,
        setBaseUrl,
        setModel,
        persistSettings,
        reload,
      }) satisfies Ctx,
    [baseUrl, model, ready, setBaseUrl, setModel, persistSettings, reload]
  )

  return (
    <OllamaSettingsContext.Provider value={value}>{children}</OllamaSettingsContext.Provider>
  )
}

export function useOllamaSettings() {
  const ctx = React.useContext(OllamaSettingsContext)
  if (!ctx) throw new Error("useOllamaSettings must be used within OllamaSettingsProvider")
  return ctx
}
