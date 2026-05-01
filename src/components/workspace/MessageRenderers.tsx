"use client"

import * as React from "react"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { Loader2, Play, TerminalSquare } from "lucide-react"

export type MessageBlock =
  | { type: "text"; content: string }
  | {
      type: "cve_table"
      rows: Record<string, unknown>[]
    }
  | {
      type: "script_run"
      project: string
      status: "running" | "done" | "error"
      detail?: string
    }
  | {
      type: "confirm_execution"
      id: string
      summary: string
      commandPreview: string
      payload: {
        projectName: string
        scriptType: string
        intelxQuery?: string | null
        intelxStartDate?: string | null
        intelxEndDate?: string | null
        intelxSearchLimit?: string | null
        socialMediaTarget?: string | null
        socialMediaStartDate?: string | null
        socialMediaEndDate?: string | null
        socialMediaNumPerPlatform?: string | null
        phishingScanType?: string | null
        phishingDomains?: string | null
        phishingKeywords?: string | null
        phishingStartDate?: string | null
        phishingEndDate?: string | null
      }
    }

export function MessageBlockView({
  block,
  onConfirmExecution,
}: {
  block: MessageBlock
  onConfirmExecution?: (block: Extract<MessageBlock, { type: "confirm_execution" }>) => void
}) {
  switch (block.type) {
    case "text":
      return (
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground/95">
          {block.content}
        </p>
      )
    case "cve_table": {
      if (!block.rows.length) return null
      const keys = Object.keys(block.rows[0] ?? {})
      return (
        <div className="mt-2 overflow-hidden rounded-md border border-white/10 bg-black/30">
          <Table>
            <TableHeader>
              <TableRow className="border-white/10 hover:bg-transparent">
                {keys.slice(0, 5).map((k) => (
                  <TableHead
                    key={k}
                    className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground h-8"
                  >
                    {k}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {block.rows.slice(0, 8).map((row, i) => (
                <TableRow key={i} className="border-white/5 font-mono text-[11px]">
                  {keys.slice(0, 5).map((k) => (
                    <TableCell key={k} className="max-w-[140px] truncate py-1.5">
                      {String((row as Record<string, unknown>)[k] ?? "")}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )
    }
    case "script_run":
      return (
        <div
          className={cn(
            "mt-2 flex items-center gap-2 rounded-lg border border-white/10 bg-black/25 px-3 py-2 font-mono text-[11px]",
            block.status === "error" && "border-red-500/40 bg-red-950/20"
          )}
        >
          {block.status === "running" ? (
            <Loader2 className="size-3.5 shrink-0 animate-spin text-cyan-400" />
          ) : (
            <TerminalSquare className="size-3.5 shrink-0 text-muted-foreground" />
          )}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-cyan-300/90">{block.project}</span>
              <Badge variant="outline" className="text-[9px] h-5 px-1.5">
                {block.status}
              </Badge>
            </div>
            {block.detail ? (
              <p className="mt-0.5 truncate text-muted-foreground">{block.detail}</p>
            ) : null}
          </div>
        </div>
      )
    case "confirm_execution":
      return (
        <div className="mt-3 rounded-lg border border-amber-500/35 bg-amber-950/15 p-3">
          <p className="text-xs font-medium text-amber-100/90">{block.summary}</p>
          <pre className="mt-2 max-h-40 overflow-auto rounded border border-white/10 bg-black/40 p-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
            {block.commandPreview}
          </pre>
          <Button
            size="sm"
            className="mt-3 h-8 gap-1.5 bg-amber-600 text-black hover:bg-amber-500"
            onClick={() => onConfirmExecution?.(block)}
          >
            <Play className="size-3.5" />
            Confirm execution
          </Button>
        </div>
      )
    default:
      return null
  }
}
