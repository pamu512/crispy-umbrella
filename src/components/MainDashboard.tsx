"use client"

import * as React from "react"
import { invoke } from "@tauri-apps/api/core"

import { OperationsOverview, type DashboardMetrics } from "@/components/OperationsOverview"
import { useWorkspace } from "@/components/WorkspaceProvider"

export function MainDashboard() {
  const { workspacePath } = useWorkspace()
  const [metrics, setMetrics] = React.useState<DashboardMetrics | null>(null)
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  const loadVector = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const m = await invoke<DashboardMetrics>("get_dashboard_metrics", {
        workspacePath: workspacePath?.trim() ?? "",
      })
      setMetrics(m)
    } catch (e) {
      setMetrics(null)
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [workspacePath])

  React.useEffect(() => {
    void loadVector()
  }, [loadVector])

  return (
    <>
      {error ? (
        <div
          role="alert"
          className="border-b border-red-500/30 bg-red-950/50 px-4 py-2 font-mono text-xs text-red-100"
        >
          Vector metrics: {error}
        </div>
      ) : null}
      <OperationsOverview
        vectorMetrics={metrics}
        vectorLoading={loading}
        onRefreshVector={() => void loadVector()}
      />
    </>
  )
}
