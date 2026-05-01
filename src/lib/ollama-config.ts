/** Normalize user-entered Ollama API base (no trailing slash, default scheme). */
export function normalizeOllamaBaseUrl(raw: string): string {
  let u = raw.trim()
  if (!u) return "http://127.0.0.1:11434"
  if (!/^https?:\/\//i.test(u)) {
    u = `http://${u}`
  }
  u = u.replace(/\/+$/, "")
  return u
}

export function ollamaChatUrl(base: string): string {
  return `${normalizeOllamaBaseUrl(base)}/api/chat`
}

export function ollamaTagsUrl(base: string): string {
  return `${normalizeOllamaBaseUrl(base)}/api/tags`
}

export const OLLAMA_DEFAULT_BASE = "http://127.0.0.1:11434"
/** Safer default than a huge quant model tag that may not be pulled. */
export const OLLAMA_DEFAULT_MODEL = "llama3.1"
