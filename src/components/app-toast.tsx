"use client"

import * as React from "react"
import { CheckCircle2, XCircle } from "lucide-react"

export type AppToastInput = {
  variant: "success" | "error"
  title: string
  message?: string
}

type AppToastItem = AppToastInput & { id: number }

const ToastContext = React.createContext<(t: AppToastInput) => void>(() => {})

export function AppToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<AppToastItem[]>([])
  const seq = React.useRef(0)

  const push = React.useCallback((t: AppToastInput) => {
    const id = ++seq.current
    setItems((prev) => [...prev, { ...t, id }])
    window.setTimeout(() => {
      setItems((prev) => prev.filter((x) => x.id !== id))
    }, 6500)
  }, [])

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div
        className="pointer-events-none fixed left-1/2 top-14 z-[200] flex w-[min(100vw-1.5rem,28rem)] -translate-x-1/2 flex-col gap-2 px-2"
        aria-live="polite"
      >
        {items.map((t) => (
          <div
            key={t.id}
            className={
              "pointer-events-auto flex gap-3 rounded-lg border px-3 py-2.5 shadow-lg backdrop-blur-md " +
              (t.variant === "success"
                ? "border-emerald-500/35 bg-emerald-950/90 text-emerald-50"
                : "border-red-500/40 bg-red-950/90 text-red-50")
            }
          >
            {t.variant === "success" ? (
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-400" aria-hidden />
            ) : (
              <XCircle className="mt-0.5 size-4 shrink-0 text-red-400" aria-hidden />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold leading-tight">{t.title}</p>
              {t.message ? (
                <p className="mt-1 font-mono text-[11px] leading-snug opacity-90">{t.message}</p>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useAppToast() {
  return React.useContext(ToastContext)
}
