import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace"

/**
 * CTI Command Center: vitals bar, **Barney** (fixed left rail), scrollable **Data Ingestion Hub**, **live alerts**,
 * **Data Lab** drawer (tools), embedded console (`PersistentAppLayout` + `InvestigationWorkspace`).
 */
export default function Home() {
  return (
    <div className="flex h-screen min-h-0 w-full flex-1 flex-col overflow-y-auto">
      <InvestigationWorkspace />
    </div>
  )
}
