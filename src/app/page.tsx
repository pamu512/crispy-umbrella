import { OllamaSettingsProvider } from "@/components/OllamaSettingsProvider"
import { WorkspaceProvider } from "@/components/WorkspaceProvider"
import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace"

export default function Home() {
  return (
    <OllamaSettingsProvider>
      <WorkspaceProvider>
        <InvestigationWorkspace />
      </WorkspaceProvider>
    </OllamaSettingsProvider>
  )
}
