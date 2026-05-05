"use client"

import React, { useState } from "react"
import { invokeSearchVault } from "@/lib/vault-search"
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

    const q = query.trim()

    try {
      const allResults: SearchResult[] = []

      const cves = await invokeSearchVault({ workspacePath, entity: "cveData", textContains: q, limit: 5 }).catch(
        () => [] as Record<string, unknown>[]
      )
      cves.forEach((r) =>
        allResults.push({
          source: "CVE",
          title: String(r.cve_id ?? ""),
          details: String(r.metadata ?? "No metadata"),
        })
      )

      const leaks = await invokeSearchVault({
        workspacePath,
        entity: "ransomwareVictims",
        textContains: q,
        limit: 5,
      }).catch(() => [] as Record<string, unknown>[])

      leaks.forEach((r) =>
        allResults.push({
          source: "Ransomware",
          title: String(r.company ?? ""),
          details: `Group: ${String(r.group_name ?? "")}`,
        })
      )

      const assets = await invokeSearchVault({ workspacePath, entity: "asmAssets", textContains: q, limit: 5 }).catch(
        () => [] as Record<string, unknown>[]
      )
      assets.forEach((r) =>
        allResults.push({
          source: "Asset",
          title: String(r.asset_target ?? ""),
          details: String(r.metadata ?? ""),
        })
      )

      const iocs = await invokeSearchVault({ workspacePath, entity: "iocsLegacy", textContains: q, limit: 5 }).catch(
        () => [] as Record<string, unknown>[]
      )
      iocs.forEach((r) =>
        allResults.push({
          source: "IOC",
          title: String(r.ioc_value ?? ""),
          details: `Type: ${String(r.type ?? "")}`,
        })
      )

      const iocRec = await invokeSearchVault({ workspacePath, entity: "iocRecords", textContains: q, limit: 5 }).catch(
        () => [] as Record<string, unknown>[]
      )
      iocRec.forEach((r) =>
        allResults.push({
          source: "IOC record",
          title: String(r.ioc_value ?? ""),
          details: `${String(r.ioc_type ?? "")} — ${String(r.metadata ?? "")}`,
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
