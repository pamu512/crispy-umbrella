"use client"

import React, { useEffect, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import { useWorkspace } from "./WorkspaceProvider"
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "./ui/card"
import { Button } from "./ui/button"
import { Badge } from "./ui/badge"
import { IntelxRunDialog } from "@/components/workspace/IntelxRunDialog"
import { SocialMediaRunDialog } from "@/components/workspace/SocialMediaRunDialog"
import { PhishingRunDialog } from "@/components/workspace/PhishingRunDialog"
import { CompromisedUserMacRunDialog } from "@/components/workspace/CompromisedUserMacRunDialog"
import { invokeRunProject } from "@/lib/run-project"
import { formatInvokeError } from "@/lib/invoke-error"

const PROJECTS = [
  { name: "Intelx_Crawler", type: "sh" },
  { name: "CVE_Project_NVD", type: "python" },
  { name: "ASM-fetch-main", type: "python" },
  { name: "Ransomware_live_event_victim", type: "python" },
  { name: "Phishing_and_Social_Media_All-in-one", type: "python" },
  { name: "Social_MediaV2", type: "python" },
  { name: "IOCs-crawler-main", type: "python" },
  { name: "Compromised_user_Mac", type: "python" },
]

interface ProjectStatus {
  name: string
  exists: boolean
}

export function ProjectHub() {
  const { workspacePath, scriptsRoot } = useWorkspace()
  const [statuses, setStatuses] = useState<Record<string, boolean>>({})
  const [running, setRunning] = useState<Record<string, boolean>>({})
  const [intelxOpen, setIntelxOpen] = useState(false)
  const [socialOpen, setSocialOpen] = useState(false)
  const [phishingOpen, setPhishingOpen] = useState(false)
  const [rumarkOpen, setRumarkOpen] = useState(false)
  const [hubError, setHubError] = useState<string | null>(null)

  useEffect(() => {
    if (!workspacePath) return
    const req = scriptsRoot
      ? invoke<ProjectStatus[]>("validate_features_bundle")
      : invoke<ProjectStatus[]>("validate_workspace", { path: workspacePath })
    req
      .then((res) => {
        const sm: Record<string, boolean> = {}
        res.forEach((r) => {
          sm[r.name] = r.exists
        })
        setStatuses(sm)
      })
      .catch((err) => console.warn("[workspace]", formatInvokeError(err)))
  }, [workspacePath, scriptsRoot])

  const runProject = async (name: string, type: string) => {
    if (!workspacePath) return
    if (name === "Intelx_Crawler") {
      setIntelxOpen(true)
      return
    }
    if (name === "Social_MediaV2") {
      setSocialOpen(true)
      return
    }
    if (name === "Phishing_and_Social_Media_All-in-one") {
      setPhishingOpen(true)
      return
    }
    if (name === "Compromised_user_Mac") {
      setRumarkOpen(true)
      return
    }

    setHubError(null)
    setRunning((prev) => ({ ...prev, [name]: true }))
    try {
      await invokeRunProject(workspacePath, name, type, null, null, null, null, {
        scriptsRoot: scriptsRoot ?? undefined,
      })
    } catch (e) {
      setHubError(`${name}: ${formatInvokeError(e)}`)
      if (process.env.NODE_ENV === "development") {
        console.warn("[CTI script]", name, formatInvokeError(e))
      }
    } finally {
      setTimeout(() => setRunning((prev) => ({ ...prev, [name]: false })), 3000)
    }
  }

  return (
    <div className="space-y-3">
      {hubError ? (
        <p className="rounded border border-red-500/30 bg-red-950/20 px-3 py-2 font-mono text-xs text-red-200">
          {hubError}
        </p>
      ) : null}
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {PROJECTS.map((p) => (
        <Card key={p.name} className="flex flex-col">
          <CardHeader className="pb-2">
            <CardTitle className="truncate text-base" title={p.name}>
              {p.name}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col justify-center space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Status:</span>
              {statuses[p.name] === undefined ? (
                <Badge variant="outline">Checking</Badge>
              ) : statuses[p.name] ? (
                <Badge variant="default" className="bg-green-600">
                  Ready
                </Badge>
              ) : (
                <Badge variant="destructive">Missing</Badge>
              )}
            </div>
            <div className="text-xs italic text-muted-foreground">No recent CSV data</div>
          </CardContent>
          <CardFooter>
            <Button
              className="w-full"
              size="sm"
              disabled={!statuses[p.name] || running[p.name]}
              onClick={() => void runProject(p.name, p.type)}
            >
              {running[p.name] ? "Running..." : "Run Now"}
            </Button>
          </CardFooter>
        </Card>
      ))}
    </div>
      <IntelxRunDialog
        open={intelxOpen}
        onOpenChange={setIntelxOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          setRunning((prev) => ({ ...prev, Intelx_Crawler: true }))
          setTimeout(
            () => setRunning((prev) => ({ ...prev, Intelx_Crawler: false })),
            3000
          )
        }}
      />
      <SocialMediaRunDialog
        open={socialOpen}
        onOpenChange={setSocialOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          setRunning((prev) => ({ ...prev, Social_MediaV2: true }))
          setTimeout(
            () => setRunning((prev) => ({ ...prev, Social_MediaV2: false })),
            3000
          )
        }}
      />
      <PhishingRunDialog
        open={phishingOpen}
        onOpenChange={setPhishingOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          setRunning((prev) => ({ ...prev, "Phishing_and_Social_Media_All-in-one": true }))
          setTimeout(
            () => setRunning((prev) => ({ ...prev, "Phishing_and_Social_Media_All-in-one": false })),
            3000
          )
        }}
      />
      <CompromisedUserMacRunDialog
        open={rumarkOpen}
        onOpenChange={setRumarkOpen}
        workspacePath={workspacePath}
        onStarted={() => {
          setRunning((prev) => ({ ...prev, "Compromised_user_Mac": true }))
          setTimeout(
            () => setRunning((prev) => ({ ...prev, "Compromised_user_Mac": false })),
            3000
          )
        }}
      />
    </div>
  )
}
