"use client"

import * as React from "react"

import { ScriptConsoleProvider } from "@/components/workspace/ScriptConsoleProvider"
import { ConsoleDrawerProvider } from "@/components/workspace/console-drawer-context"
import { TelemetryPulseProvider, useTelemetryPulse } from "@/components/workspace/telemetry-pulse-context"

function AppShellWithTelemetry({ children }: { children: React.ReactNode }) {
  const { bumpTelemetry } = useTelemetryPulse()
  return (
    <ScriptConsoleProvider onLog={bumpTelemetry}>
      <div className="flex h-screen w-full min-h-0 overflow-hidden bg-[oklch(0.07_0.01_260)] text-foreground">
        <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden bg-[oklch(0.07_0.01_260)] text-foreground">
          {children}
        </main>
      </div>
    </ScriptConsoleProvider>
  )
}

/**
 * Full-width shell: Barney and vitals live in {@link InvestigationWorkspace}; script console is global.
 */
export function PersistentAppLayout({ children }: { children: React.ReactNode }) {
  return (
    <TelemetryPulseProvider>
      <ConsoleDrawerProvider>
        <AppShellWithTelemetry>{children}</AppShellWithTelemetry>
      </ConsoleDrawerProvider>
    </TelemetryPulseProvider>
  )
}
