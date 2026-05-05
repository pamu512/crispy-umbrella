"use client"

import * as React from "react"

type TelemetryPulseContextValue = {
  pulseToken: number
  bumpTelemetry: () => void
}

const TelemetryPulseContext = React.createContext<TelemetryPulseContextValue | null>(null)

export function TelemetryPulseProvider({ children }: { children: React.ReactNode }) {
  const [pulseToken, setPulseToken] = React.useState(0)
  const bumpTelemetry = React.useCallback(() => {
    setPulseToken(Date.now())
  }, [])
  const value = React.useMemo(
    () => ({ pulseToken, bumpTelemetry }),
    [pulseToken, bumpTelemetry]
  )
  return <TelemetryPulseContext.Provider value={value}>{children}</TelemetryPulseContext.Provider>
}

export function useTelemetryPulse() {
  const ctx = React.useContext(TelemetryPulseContext)
  if (!ctx) {
    throw new Error("useTelemetryPulse must be used within TelemetryPulseProvider")
  }
  return ctx
}
