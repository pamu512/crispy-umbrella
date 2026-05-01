"use client"

import * as React from "react"
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { useWorkspace } from "@/components/WorkspaceProvider"
import { searchVault, type VaultSearchResult } from "@/lib/vault-search"
import { Badge } from "@/components/ui/badge"

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
}) {
  const { workspacePath } = useWorkspace()
  const [q, setQ] = React.useState("")
  const [results, setResults] = React.useState<VaultSearchResult[]>([])
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => {
    if (!open) {
      setQ("")
      setResults([])
      return
    }
  }, [open])

  React.useEffect(() => {
    if (!workspacePath || !q.trim()) {
      setResults([])
      return
    }
    const t = window.setTimeout(() => {
      setLoading(true)
      void searchVault(workspacePath, q)
        .then(setResults)
        .finally(() => setLoading(false))
    }, 280)
    return () => window.clearTimeout(t)
  }, [q, workspacePath])

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Vault search"
      description="Jump to records in cti_vault.db"
    >
      <Command shouldFilter={false}>
        <CommandInput
          placeholder="Search CVEs, victims, assets, IOCs…"
          value={q}
          onValueChange={setQ}
        />
        <CommandList>
          <CommandEmpty>
            {loading ? "Searching…" : q.trim() ? "No matches." : "Type to search the vault."}
          </CommandEmpty>
          <CommandGroup heading="Results">
            {results.map((r, i) => (
              <CommandItem
                key={`${r.source}-${r.title}-${i}`}
                value={`${r.source} ${r.title} ${r.details}`}
                onSelect={() => onOpenChange(false)}
                className="flex flex-col items-start gap-1 py-2"
              >
                <div className="flex w-full items-center gap-2">
                  <span className="truncate font-mono text-xs font-medium">{r.title}</span>
                  <Badge variant="outline" className="ml-auto shrink-0 text-[9px]">
                    {r.source}
                  </Badge>
                </div>
                <span className="line-clamp-2 font-mono text-[10px] text-muted-foreground">
                  {r.details}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  )
}
