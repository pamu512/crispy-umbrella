/** SQLite / JSON may return CVSS as number or string (e.g. "8.8 (HIGH)"). */

export function cvssNumeric(score: unknown): number | null {
  if (score == null) return null
  if (typeof score === "number" && Number.isFinite(score)) return score
  if (typeof score === "string") {
    const m = score.trim().match(/^([\d.]+)/)
    if (m) {
      const n = parseFloat(m[1])
      return Number.isFinite(n) ? n : null
    }
  }
  return null
}

export function formatCvssBadge(score: unknown): string {
  const n = cvssNumeric(score)
  if (n != null) return n.toFixed(1)
  if (typeof score === "string" && score.trim()) {
    const t = score.trim()
    return t.length > 16 ? `${t.slice(0, 14)}…` : t
  }
  return "—"
}
