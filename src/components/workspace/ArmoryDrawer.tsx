"use client"

import * as React from "react"
import { X } from "lucide-react"

import { NativeTerminal } from "@/components/NativeTerminal"
import { ProjectToolbox } from "@/components/workspace/ProjectToolbox"
import { Button } from "@/components/ui/button"

/** Slide-out Data Lab: CTI tools + host log (vault ingestion hub lives in the main scroll column). */
export function ArmoryDrawer(props: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onScriptActivity: () => void
}) {
  const { open, onOpenChange, onScriptActivity } = props

  return (
    <>
      {open ? (
        <button
          type="button"
          className="fixed inset-0 z-40 bg-black/55 backdrop-blur-[1px]"
          aria-label="Close Data Lab"
          onClick={() => onOpenChange(false)}
        />
      ) : null}

      <div
        className={
          "fixed left-0 top-0 z-50 flex h-screen w-[min(100vw,440px)] flex-col border-r border-white/10 bg-[oklch(0.08_0.01_260)] shadow-2xl transition-transform duration-200 ease-out " +
          (open ? "translate-x-0" : "-translate-x-full pointer-events-none")
        }
        aria-hidden={!open}
      >
        <div className="flex h-10 shrink-0 items-center justify-between border-b border-white/10 px-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-200">Data Lab</p>
            <p className="text-[9px] text-muted-foreground">Armory · project tools</p>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 text-muted-foreground"
            onClick={() => onOpenChange(false)}
          >
            <X className="size-4" />
          </Button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="min-h-0 flex-1 border-b border-white/10">
            <ProjectToolbox
              layoutVariant="drawer"
              collapsed={false}
              onCollapsedChange={() => {}}
              onScriptActivity={onScriptActivity}
            />
          </div>
        </div>

        <div className="shrink-0 border-t border-white/10 bg-[oklch(0.06_0.01_260)] px-1.5 pb-1.5 pt-1">
          <NativeTerminal compact title="Host log" />
        </div>
      </div>
    </>
  )
}
