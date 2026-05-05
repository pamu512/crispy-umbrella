/**
 * Strip common LLM artifacts: self-rubrics wrapped as `*( … )*` (with nested parentheses inside).
 * Keeps analyst-facing prose only for Barney UIs.
 */
export function sanitizeBarneyAssistantText(raw: string): string {
  const OPEN = "*("
  let s = raw
  for (;;) {
    const start = s.indexOf(OPEN)
    if (start === -1) break
    let depth = 1
    let i = start + OPEN.length
    while (i < s.length && depth > 0) {
      const c = s[i]
      if (c === "(") depth += 1
      else if (c === ")") depth -= 1
      i += 1
    }
    if (depth !== 0 || i > s.length) break
    if (s[i] === "*") {
      s = s.slice(0, start) + s.slice(i + 1)
    } else {
      break
    }
  }
  return s.replace(/\n{3,}/g, "\n\n").trim()
}
