/** Normalize Tauri / invoke failures for display (avoid raw console.error in dev). */

export function formatInvokeError(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === "string") return e
  try {
    return JSON.stringify(e)
  } catch {
    return String(e)
  }
}
