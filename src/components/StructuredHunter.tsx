"use client"

import * as React from "react"
import { Braces, Copy, Plus, Trash2 } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"

/** AST schema version sent to the backend. */
export const STRUCTURED_HUNT_AST_VERSION = 1 as const

/** Stable field identifiers (wire format). */
export type HuntFieldId =
  | "threat_actor"
  | "severity"
  | "ioc_type"
  | "ioc_value"
  | "cve_id"
  | "asset_target"
  | "source_project"
  | "ingested_after"

/** Stable operator identifiers (wire format). */
export type HuntOperatorId =
  | "eq"
  | "neq"
  | "contains"
  | "starts_with"
  | "ends_with"
  | "gt"
  | "gte"
  | "lt"
  | "lte"

/** Leaf predicate in the hunt AST. */
export type HuntPredicateNode = {
  type: "predicate"
  field: HuntFieldId
  operator: HuntOperatorId
  /** Normalized string; numbers (e.g. CVSS) are still strings at the AST boundary. */
  value: string
}

/** Logical grouping (left-associative fold of the UI rows). */
export type HuntGroupNode = {
  type: "group"
  op: "and" | "or"
  children: HuntAstNode[]
}

export type HuntAstNode = HuntPredicateNode | HuntGroupNode

/** Root document returned to the backend / parent. */
export type StructuredHuntAstRoot = {
  schemaVersion: typeof STRUCTURED_HUNT_AST_VERSION
  tree: HuntAstNode
}

const FIELD_OPTIONS: { id: HuntFieldId; label: string }[] = [
  { id: "threat_actor", label: "Threat Actor" },
  { id: "severity", label: "Severity" },
  { id: "ioc_type", label: "IOC Type" },
  { id: "ioc_value", label: "IOC Value" },
  { id: "cve_id", label: "CVE ID" },
  { id: "asset_target", label: "Asset / Target" },
  { id: "source_project", label: "Source Project" },
  { id: "ingested_after", label: "Ingested After (ISO date)" },
]

const OPERATOR_OPTIONS: { id: HuntOperatorId; label: string }[] = [
  { id: "eq", label: "Equals" },
  { id: "neq", label: "Not equals" },
  { id: "contains", label: "Contains" },
  { id: "starts_with", label: "Starts with" },
  { id: "ends_with", label: "Ends with" },
  { id: "gt", label: "Greater than" },
  { id: "gte", label: "Greater or equal" },
  { id: "lt", label: "Less than" },
  { id: "lte", label: "Less or equal" },
]

const DEFAULT_OPERATORS_BY_FIELD: Record<HuntFieldId, HuntOperatorId[]> = {
  threat_actor: ["eq", "neq", "contains"],
  severity: ["eq", "neq", "gt", "gte", "lt", "lte", "contains"],
  ioc_type: ["eq", "neq", "contains", "starts_with"],
  ioc_value: ["eq", "neq", "contains", "starts_with", "ends_with"],
  cve_id: ["eq", "neq", "contains", "starts_with"],
  asset_target: ["eq", "neq", "contains", "starts_with"],
  source_project: ["eq", "neq", "contains"],
  ingested_after: ["eq", "gte", "lte", "gt", "lt"],
}

function rowId(): string {
  return `hunt_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`
}

export type HuntConditionRow = {
  id: string
  field: HuntFieldId
  operator: HuntOperatorId
  value: string
}

function defaultRow(): HuntConditionRow {
  return {
    id: rowId(),
    field: "threat_actor",
    operator: "eq",
    value: "",
  }
}

function firstOperatorForField(field: HuntFieldId): HuntOperatorId {
  const allowed = DEFAULT_OPERATORS_BY_FIELD[field]
  return allowed[0] ?? "eq"
}

/** Drop empty value rows; trim meaningful rows. */
function sanitizeRows(rows: HuntConditionRow[]): HuntConditionRow[] {
  return rows
    .map((r) => ({
      ...r,
      value: r.value.trim(),
    }))
    .filter((r) => r.value.length > 0)
}

/**
 * Fold UI rows + combinators into a strict AST (left-associative).
 * Example: rows [A,B,C], ops [and, or] → or(and(A,B), C)
 */
export function compileStructuredHuntAst(
  rows: HuntConditionRow[],
  combinators: ("and" | "or")[]
): StructuredHuntAstRoot {
  const active = sanitizeRows(rows)
  if (active.length === 0) {
    return {
      schemaVersion: STRUCTURED_HUNT_AST_VERSION,
      tree: { type: "group", op: "and", children: [] },
    }
  }

  const predicates: HuntPredicateNode[] = active.map((r) => ({
    type: "predicate" as const,
    field: r.field,
    operator: r.operator,
    value: r.value,
  }))

  if (predicates.length === 1) {
    return { schemaVersion: STRUCTURED_HUNT_AST_VERSION, tree: predicates[0] }
  }

  let acc: HuntAstNode = predicates[0]
  for (let i = 1; i < predicates.length; i++) {
    const op = combinators[i - 1] ?? "and"
    acc = { type: "group", op, children: [acc, predicates[i]] }
  }
  return { schemaVersion: STRUCTURED_HUNT_AST_VERSION, tree: acc }
}

const selectClass = cn(
  "h-9 w-full min-w-0 rounded-md border border-white/15 bg-black/40 px-2 font-mono text-xs",
  "text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/60"
)

export interface StructuredHunterProps {
  /** Fires when the compiled AST changes (including on mount). */
  onAstChange?: (ast: StructuredHuntAstRoot) => void
  className?: string
}

export function StructuredHunter({ onAstChange, className }: StructuredHunterProps) {
  const [rows, setRows] = React.useState<HuntConditionRow[]>(() => [defaultRow()])
  const [combinators, setCombinators] = React.useState<("and" | "or")[]>([])

  React.useEffect(() => {
    const next = combinators.length
    const need = Math.max(0, rows.length - 1)
    if (next === need) return
    setCombinators((prev) => {
      if (need > prev.length) {
        return [...prev, ...Array.from({ length: need - prev.length }, () => "and" as const)]
      }
      return prev.slice(0, need)
    })
  }, [rows.length, combinators.length])

  const ast = React.useMemo(() => compileStructuredHuntAst(rows, combinators), [rows, combinators])

  React.useEffect(() => {
    onAstChange?.(ast)
  }, [ast, onAstChange])

  const json = React.useMemo(() => JSON.stringify(ast, null, 2), [ast])

  const updateRow = React.useCallback((id: string, patch: Partial<HuntConditionRow>) => {
    setRows((prev) =>
      prev.map((r) => {
        if (r.id !== id) return r
        const next = { ...r, ...patch }
        if (patch.field != null && patch.field !== r.field) {
          const allowed = DEFAULT_OPERATORS_BY_FIELD[patch.field]
          if (!allowed.includes(next.operator)) {
            next.operator = firstOperatorForField(patch.field)
          }
        }
        return next
      })
    )
  }, [])

  const addRow = React.useCallback(() => {
    setRows((prev) => [...prev, defaultRow()])
  }, [])

  const removeRow = React.useCallback((id: string) => {
    setRows((prev) => {
      if (prev.length <= 1) return prev
      return prev.filter((r) => r.id !== id)
    })
  }, [])

  const setCombinator = React.useCallback((index: number, op: "and" | "or") => {
    setCombinators((prev) => {
      const copy = [...prev]
      copy[index] = op
      return copy
    })
  }, [])

  const copyJson = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(json)
    } catch {
      /* ignore */
    }
  }, [json])

  return (
    <Card
      className={cn(
        "border-white/10 bg-gradient-to-b from-zinc-950/90 to-black/80 text-zinc-100 shadow-lg shadow-black/40 ring-1 ring-white/5",
        className
      )}
    >
      <CardHeader className="border-b border-white/10 pb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base tracking-tight text-white">
              <Braces className="size-4 text-cyan-400" aria-hidden />
              Structured Hunter
            </CardTitle>
            <CardDescription className="text-xs text-zinc-400">
              Build logic blocks with explicit fields and operators. The panel compiles a versioned JSON AST for the
              backend—no free-form SQL.
            </CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" className="shrink-0 border-white/15 bg-black/30" onClick={copyJson}>
            <Copy className="size-3.5" />
            Copy AST
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4 pt-4">
        <ScrollArea className="max-h-[min(420px,55vh)] pr-3">
          <div className="space-y-0 pb-1">
            {rows.map((row, index) => (
              <React.Fragment key={row.id}>
                {index > 0 ? (
                  <div className="flex items-center justify-center py-2">
                    <div className="flex h-8 items-center gap-2 rounded-full border border-cyan-500/25 bg-cyan-950/40 px-2 ring-1 ring-cyan-500/10">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-cyan-300/90">Join</span>
                      <select
                        aria-label={`Combinator before row ${index + 1}`}
                        className={cn(selectClass, "h-8 w-[7.5rem] border-cyan-500/20 bg-black/50 text-[11px]")}
                        value={combinators[index - 1] ?? "and"}
                        onChange={(e) => setCombinator(index - 1, e.target.value as "and" | "or")}
                      >
                        <option value="and">AND</option>
                        <option value="or">OR</option>
                      </select>
                    </div>
                  </div>
                ) : null}

                <div
                  className={cn(
                    "rounded-lg border border-white/10 bg-black/35 p-3 ring-1 ring-white/5",
                    "backdrop-blur-sm"
                  )}
                >
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-zinc-500">
                      Block {index + 1}
                    </span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      className="text-zinc-500 hover:bg-red-950/40 hover:text-red-300"
                      disabled={rows.length <= 1}
                      onClick={() => removeRow(row.id)}
                      aria-label="Remove block"
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1.2fr)] sm:items-end">
                    <div className="grid gap-1.5">
                      <Label className="text-[11px] text-zinc-400">Field</Label>
                      <select
                        className={selectClass}
                        value={row.field}
                        onChange={(e) => updateRow(row.id, { field: e.target.value as HuntFieldId })}
                      >
                        {FIELD_OPTIONS.map((f) => (
                          <option key={f.id} value={f.id}>
                            {f.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="grid gap-1.5">
                      <Label className="text-[11px] text-zinc-400">Operator</Label>
                      <select
                        className={selectClass}
                        value={row.operator}
                        onChange={(e) => updateRow(row.id, { operator: e.target.value as HuntOperatorId })}
                      >
                        {OPERATOR_OPTIONS.filter((o) => DEFAULT_OPERATORS_BY_FIELD[row.field].includes(o.id)).map(
                          (o) => (
                            <option key={o.id} value={o.id}>
                              {o.label}
                            </option>
                          )
                        )}
                      </select>
                    </div>
                    <div className="grid gap-1.5 sm:col-span-1">
                      <Label className="text-[11px] text-zinc-400">Value</Label>
                      <Input
                        className="border-white/15 bg-black/40 font-mono text-xs text-zinc-100 placeholder:text-zinc-600"
                        placeholder="e.g. APT29, 7.0, CVE-2024-…"
                        value={row.value}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                        autoComplete="off"
                      />
                    </div>
                  </div>
                </div>
              </React.Fragment>
            ))}
          </div>
        </ScrollArea>

        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="w-full border border-white/10 bg-zinc-900/80 text-zinc-100 hover:bg-zinc-800"
          onClick={addRow}
        >
          <Plus className="size-3.5" />
          Add block
        </Button>
      </CardContent>

      <CardFooter className="flex-col items-stretch gap-2 border-t border-white/10 bg-black/25 pt-4">
        <div className="flex items-center justify-between gap-2">
          <Label className="text-[11px] font-semibold uppercase tracking-widest text-zinc-500">Compiled AST</Label>
          <span className="font-mono text-[10px] text-zinc-500">schemaVersion {STRUCTURED_HUNT_AST_VERSION}</span>
        </div>
        <pre
          className={cn(
            "max-h-52 overflow-auto rounded-md border border-white/10 bg-zinc-950/90 p-3 font-mono text-[11px] leading-relaxed",
            "text-emerald-200/90 selection:bg-cyan-900/50"
          )}
          tabIndex={0}
        >
          {json}
        </pre>
      </CardFooter>
    </Card>
  )
}
