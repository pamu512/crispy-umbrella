"use client"

import * as React from "react"
import dynamic from "next/dynamic"
import { invoke } from "@tauri-apps/api/core"
import type { ForceGraphMethods } from "react-force-graph-2d"

import { cn } from "@/lib/utils"

/** Payload from Tauri `get_pivot_graph` (`#[serde(rename_all = "camelCase")]`). */
export interface PivotGraphBackendNode {
  id: string
  label: string
  type: string
}

export interface PivotGraphBackendEdge {
  sourceId: string
  targetId: string
  relationshipType: string
}

export interface PivotGraphBackendPayload {
  nodes: PivotGraphBackendNode[]
  edges: PivotGraphBackendEdge[]
}

export type ForceGraphNode = PivotGraphBackendNode & {
  x?: number
  y?: number
}

export type ForceGraphLink = {
  source: string
  target: string
  relationshipType: string
}

const ForceGraph2D = dynamic(
  () => import("react-force-graph-2d").then((m) => m.default),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full min-h-[320px] items-center justify-center rounded-lg border border-white/10 bg-zinc-950/80 text-sm text-zinc-500">
        Loading graph engine…
      </div>
    ),
  }
)

function colorForIocType(iocType: string): string {
  const k = iocType.trim().toLowerCase()
  switch (k) {
    case "ip":
    case "ipv4":
    case "ipv6":
      return "#2563eb" // blue-600
    case "domain":
    case "hostname":
      return "#dc2626" // red-600
    case "url":
      return "#16a34a" // green-600
    case "email":
      return "#9333ea" // purple-600
    case "hash":
    case "sha256":
    case "md5":
      return "#d97706" // amber-600
    case "news_title":
      return "#0891b2" // cyan-600
    default:
      return "#64748b" // slate-500
  }
}

function linkColor(rel: string): string {
  if (rel === "same_threat_actor") return "rgba(34, 211, 238, 0.55)"
  if (rel === "same_source_project") return "rgba(148, 163, 184, 0.45)"
  return "rgba(148, 163, 184, 0.35)"
}

export interface PivotGraphProps {
  /** `ioc_value`, or `ioc_value` + U+001F + `ioc_type` (see Rust `graph_pivot`). */
  iocId: string
  className?: string
}

export function PivotGraph({ iocId, className }: PivotGraphProps) {
  const containerRef = React.useRef<HTMLDivElement>(null)
  const fgRef = React.useRef<ForceGraphMethods | undefined>(undefined)

  const [dimensions, setDimensions] = React.useState({ width: 640, height: 480 })
  const [graphData, setGraphData] = React.useState<{ nodes: ForceGraphNode[]; links: ForceGraphLink[] }>({
    nodes: [],
    links: [],
  })
  const [status, setStatus] = React.useState<"idle" | "loading" | "ready" | "error">("idle")
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null)

  /** Load pivot graph from Tauri when `iocId` changes. */
  React.useEffect(() => {
    const id = iocId.trim()
    if (!id) {
      setGraphData({ nodes: [], links: [] })
      setStatus("idle")
      setErrorMessage(null)
      return
    }

    let cancelled = false
    setStatus("loading")
    setErrorMessage(null)

    void (async () => {
      try {
        const raw = await invoke<PivotGraphBackendPayload>("get_pivot_graph", { iocId: id })
        if (cancelled) return
        const nodes: ForceGraphNode[] = (raw.nodes ?? []).map((n) => ({
          ...n,
          type: n.type ?? "unknown",
        }))
        const links: ForceGraphLink[] = (raw.edges ?? []).map((e) => ({
          source: e.sourceId,
          target: e.targetId,
          relationshipType: e.relationshipType,
        }))
        setGraphData({ nodes, links })
        setStatus("ready")
      } catch (e) {
        if (cancelled) return
        setGraphData({ nodes: [], links: [] })
        setStatus("error")
        setErrorMessage(String(e))
      }
    })()

    return () => {
      cancelled = true
    }
  }, [iocId])

  /** Observe container size so the canvas matches layout (resize / sidebar toggles). */
  React.useEffect(() => {
    const el = containerRef.current
    if (!el) return

    const ro = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect
      if (!cr) return
      const w = Math.max(320, Math.floor(cr.width))
      const h = Math.max(280, Math.floor(cr.height))
      setDimensions({ width: w, height: h })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  /** After data or dimensions change, fit the force layout in view. */
  React.useEffect(() => {
    if (status !== "ready" || graphData.nodes.length === 0) return
    const t = window.setTimeout(() => {
      fgRef.current?.zoomToFit?.(400, 40)
    }, 120)
    return () => window.clearTimeout(t)
  }, [status, graphData, dimensions.width, dimensions.height])

  const nodeColor = React.useCallback((node: Record<string, unknown>) => {
    return colorForIocType(String(node.type ?? ""))
  }, [])

  const linkColorCb = React.useCallback((link: Record<string, unknown>) => {
    return linkColor(String(link.relationshipType ?? ""))
  }, [])

  const linkLabel = React.useCallback((link: Record<string, unknown>) => {
    return String(link.relationshipType ?? "")
  }, [])

  const nodeLabel = React.useCallback((node: Record<string, unknown>) => {
    return String(node.label ?? node.id ?? "")
  }, [])

  return (
    <div
      ref={containerRef}
      className={cn(
        "flex min-h-[360px] w-full flex-col overflow-hidden rounded-xl border border-white/10 bg-zinc-950/90 shadow-inner shadow-black/40",
        className
      )}
    >
      <div className="flex items-center justify-between gap-2 border-b border-white/10 px-3 py-2">
        <span className="text-xs font-semibold uppercase tracking-widest text-zinc-400">Pivot graph</span>
        {status === "loading" ? (
          <span className="text-[11px] text-cyan-400/90">Loading…</span>
        ) : status === "error" ? (
          <span className="max-w-[70%] truncate text-[11px] text-red-400" title={errorMessage ?? ""}>
            {errorMessage ?? "Error"}
          </span>
        ) : (
          <span className="text-[11px] text-zinc-500">
            {graphData.nodes.length} nodes · {graphData.links.length} edges
          </span>
        )}
      </div>

      <div className="relative min-h-[320px] w-full flex-1">
        {!iocId.trim() ? (
          <div className="flex h-full min-h-[320px] items-center justify-center p-6 text-center text-sm text-zinc-500">
            Enter an IOC id to load the 1-hop pivot graph.
          </div>
        ) : status === "error" ? (
          <div className="flex h-full min-h-[320px] items-center justify-center p-6 text-center text-sm text-red-300/90">
            Could not load graph. Ensure Tauri is running and <code className="rounded bg-black/40 px-1">vault_db_path</code> is set.
          </div>
        ) : (
          <ForceGraph2D
            ref={fgRef}
            width={dimensions.width}
            height={dimensions.height}
            graphData={graphData}
            backgroundColor="#030712"
            nodeId="id"
            nodeLabel={nodeLabel}
            nodeColor={nodeColor}
            nodeRelSize={6}
            linkColor={linkColorCb}
            linkWidth={1.2}
            linkDirectionalArrowLength={0}
            linkLabel={linkLabel}
            cooldownTicks={120}
            onEngineStop={() => fgRef.current?.zoomToFit?.(400, 40)}
          />
        )}
      </div>

      <div className="flex flex-wrap gap-3 border-t border-white/10 bg-black/30 px-3 py-2">
        <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">IOC type</span>
        {[
          ["IP", colorForIocType("ip")],
          ["Domain", colorForIocType("domain")],
          ["URL", colorForIocType("url")],
          ["Email", colorForIocType("email")],
          ["Other", colorForIocType("unknown")],
        ].map(([label, color]) => (
          <span key={label} className="flex items-center gap-1.5 text-[10px] text-zinc-400">
            <span className="size-2.5 rounded-full ring-1 ring-white/20" style={{ backgroundColor: color }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  )
}
