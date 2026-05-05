"use client"

import * as React from "react"

type ConsoleDrawerContextValue = {
  forcedConsole: boolean
  setForcedConsole: (v: boolean) => void
}

const ConsoleDrawerContext = React.createContext<ConsoleDrawerContextValue | null>(null)

export function ConsoleDrawerProvider({ children }: { children: React.ReactNode }) {
  const [forcedConsole, setForcedConsole] = React.useState(false)
  const value = React.useMemo(
    () => ({ forcedConsole, setForcedConsole }),
    [forcedConsole]
  )
  return <ConsoleDrawerContext.Provider value={value}>{children}</ConsoleDrawerContext.Provider>
}

export function useConsoleDrawer() {
  const ctx = React.useContext(ConsoleDrawerContext)
  if (!ctx) {
    throw new Error("useConsoleDrawer must be used within ConsoleDrawerProvider")
  }
  return ctx
}
