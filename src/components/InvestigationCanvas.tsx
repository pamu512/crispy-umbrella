"use client"

import React, { useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import { useWorkspace } from "./WorkspaceProvider"
import { Input } from "./ui/input"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { Badge } from "./ui/badge"

interface SearchResult {
  source: string
  title: string
  details: string
}

export function InvestigationCanvas() {
  const { workspacePath } = useWorkspace()
  const [query, setQuery] = useState("")
  const [results, setResults] = useState<SearchResult[]>([])
  const [searching, setSearching] = useState(false)

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim() || !workspacePath) return

    setSearching(true)
    setResults([])

    const searchTerm = `%${query}%`

    try {
      const allResults: SearchResult[] = []

      // Search CVEs
      const cves = await invoke<any[]>("query_db", {
        workspacePath,
        query: `SELECT cve_id, metadata FROM cve_data WHERE cve_id LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 5`,
      }).catch(() => [])

      cves.forEach((r) =>
        allResults.push({
          source: "CVE",
          title: r.cve_id,
          details: r.metadata || "No metadata",
        })
      )

      // Search Ransomware Leaks
      const leaks = await invoke<any[]>("query_db", {
        workspacePath,
        query: `SELECT company, group_name FROM Ransomware_live_event_victim WHERE company LIKE '${searchTerm}' OR group_name LIKE '${searchTerm}' LIMIT 5`
      }).catch(() => [])

      leaks.forEach(r => allResults.push({
        source: "Ransomware",
        title: r.company,
        details: `Group: ${r.group_name}`
      }))

      // Search Assets
      const assets = await invoke<any[]>("query_db", {
        workspacePath,
        query: `SELECT asset_target, metadata FROM asm_assets WHERE asset_target LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 5`,
      }).catch(() => [])

      assets.forEach((r) =>
        allResults.push({
          source: "Asset",
          title: r.asset_target,
          details: r.metadata || "",
        })
      )

      // Search IOCs
      const iocs = await invoke<any[]>("query_db", {
        workspacePath,
        query: `SELECT ioc_value, type FROM iocs WHERE ioc_value LIKE '${searchTerm}' LIMIT 5`
      }).catch(() => [])

      iocs.forEach((r) =>
        allResults.push({
          source: "IOC",
          title: r.ioc_value,
          details: `Type: ${r.type}`,
        })
      )

      const iocRec = await invoke<any[]>("query_db", {
        workspacePath,
        query: `SELECT ioc_value, ioc_type, metadata FROM ioc_records WHERE ioc_value LIKE '${searchTerm}' OR metadata LIKE '${searchTerm}' LIMIT 5`,
      }).catch(() => [])

      iocRec.forEach((r) =>
        allResults.push({
          source: "IOC record",
          title: r.ioc_value,
          details: `${r.ioc_type} — ${r.metadata || ""}`,
        })
      )

      setResults(allResults)
    } catch (err) {
      console.error("Search error", err)
    } finally {
      setSearching(false)
    }
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl font-semibold tracking-tight">Investigation Canvas</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={handleSearch} className="flex space-x-2">
          <Input 
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search across Leaks, Assets, CVEs, and IOCs..." 
            className="flex-1"
          />
          <Button type="submit" disabled={searching}>
            {searching ? "Searching..." : "Search"}
          </Button>
        </form>

        <div className="space-y-2 max-h-[300px] overflow-y-auto">
          {results.length > 0 ? (
            results.map((r, i) => (
              <div key={i} className="flex flex-col border rounded-md p-3 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-sm">{r.title}</span>
                  <Badge variant="secondary">{r.source}</Badge>
                </div>
                <span className="text-xs text-muted-foreground line-clamp-2">{r.details}</span>
              </div>
            ))
          ) : query && !searching && results.length === 0 ? (
            <div className="text-sm text-muted-foreground italic text-center py-4">No results found for "{query}"</div>
          ) : (
             <div className="text-sm text-muted-foreground italic text-center py-4">Enter a search term to begin investigation</div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
