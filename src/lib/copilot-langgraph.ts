/**
 * LangGraph agent for Barney (CTI Command Center investigation assistant).
 *
 * Nodes: `understand_query` → (conditional) → `tool_semantic_search` / `tool_structured_search` /
 * `tool_both_searches` / skip tools → `synthesize_answer`.
 *
 * Routing combines a lightweight Ollama JSON classification with heuristics so exact indicators
 * prefer SQLite (`search_vault`) while conceptual questions prefer semantic search (`semantic_threat_search`).
 */

import { Annotation, END, START, StateGraph } from "@langchain/langgraph"
import { invoke } from "@tauri-apps/api/core"

import { invokeSearchVault, type SearchVaultEntity, type SearchVaultParams } from "@/lib/vault-search"

// ---------------------------------------------------------------------------
// Ollama (Tauri proxy)
// ---------------------------------------------------------------------------

type OllamaChatResponse = {
  message?: { role?: string; content?: string }
}

async function invokeLocalLlm(messages: { role: string; content: string }[]): Promise<string> {
  const data = await invoke<OllamaChatResponse>("invoke_local_llm", {
    payload: {
      model: "llama3.2",
      messages,
    },
  })
  const text = data.message?.content?.trim() ?? ""
  return text
}

function stripJsonFence(raw: string): string {
  let s = raw.trim()
  if (s.startsWith("```")) {
    s = s.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "")
  }
  return s.trim()
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

export type CopilotSearchRoute = "semantic" | "structured" | "both" | "direct"

export type StructuredSearchPlan = Partial<Omit<SearchVaultParams, "workspacePath">> & {
  entity?: SearchVaultEntity
}

export type RoutingDecision = {
  route: CopilotSearchRoute
  structured: StructuredSearchPlan | null
  reason: string
}

const ROUTING_SYSTEM = `You are a router for Barney, the CTI Command Center investigation assistant.
Respond with ONE JSON object only (no markdown fences, no prose). Schema:
{"route":"semantic"|"structured"|"both"|"direct","structured":OBJECT_OR_NULL,"reason":"short"}

Rules:
- "semantic": user wants similarity, vague descriptions, trends, "threats like X", "related to", natural language hunting without exact technical identifiers.
- "structured": user gives exact filters or identifiers: CVE-IDs, IPs, domains, file hashes, specific IOC types, "CVE records where…", entity-specific tabular queries.
- "both": needs both semantic similarity and exact vault rows (e.g. "find semantically similar IOCs to this IP 1.2.3.4" or long investigative questions).
- "direct": greetings, capability questions, or questions that clearly need no database lookup.

When route is "structured" or "both", fill "structured" with a partial search object when possible:
{ "entity": "iocRecords"|"iocNews"|"cveData"|"asmAssets"|"iocsLegacy"|"ransomwareVictims", "textContains": string?, "iocType"?: string, "threatActor"?: string, "sourceProject"?: string, "limit"?: number (1-50) }
If unsure, set "structured" to null (the app will default text search on iocRecords).`

function parseRoutingJson(text: string): RoutingDecision | null {
  try {
    const obj = JSON.parse(stripJsonFence(text)) as Record<string, unknown>
    const route = obj.route
    if (route !== "semantic" && route !== "structured" && route !== "both" && route !== "direct") {
      return null
    }
    const structured =
      obj.structured != null && typeof obj.structured === "object" && !Array.isArray(obj.structured)
        ? (obj.structured as StructuredSearchPlan)
        : null
    const reason = typeof obj.reason === "string" ? obj.reason : ""
    return { route, structured, reason }
  } catch {
    return null
  }
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/
const HASH_RE = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/
const DOMAINISH_RE = /\b[a-z0-9][-a-z0-9]*\.(?:com|net|org|io|ru|cn|gov|mil)\b/i
const SEMANTIC_CUE_RE =
  /\b(similar|related|semantic|alike|like\s+threat|conceptual|roughly|about\s+threat|pattern|trends?|anything\s+like|vaguely)\b/i

function heuristicSignals(q: string): { exact: boolean; vague: boolean } {
  const exact =
    CVE_RE.test(q) || IPV4_RE.test(q) || HASH_RE.test(q) || DOMAINISH_RE.test(q) || /ioc_type|entity:/i.test(q)
  const vague = SEMANTIC_CUE_RE.test(q) || (q.length > 120 && !exact)
  return { exact, vague }
}

export function mergeRoutingHeuristics(userQuery: string, llm: RoutingDecision | null): RoutingDecision {
  const { exact, vague } = heuristicSignals(userQuery)
  const base: RoutingDecision =
    llm ??
    ({
      route: exact ? "structured" : vague ? "semantic" : "structured",
      structured: null,
      reason: "fallback (parse or model failure)",
    } satisfies RoutingDecision)

  let route = base.route
  let structured = base.structured
  const reasonParts = [base.reason]

  if (exact && route === "semantic") {
    route = vague ? "both" : "structured"
    reasonParts.push("heuristic: exact technical token → not semantic-only")
  }
  if (vague && route === "structured" && !exact) {
    route = "semantic"
    reasonParts.push("heuristic: vague language → semantic over structured-only")
  }
  if (exact && vague && route !== "direct") {
    route = "both"
    reasonParts.push("heuristic: mixed exact + vague cues → both")
  }

  if ((route === "structured" || route === "both") && !structured?.entity) {
    structured = {
      ...structured,
      entity: CVE_RE.test(userQuery) ? "cveData" : "iocRecords",
      textContains: structured?.textContains ?? (CVE_RE.test(userQuery) ? undefined : userQuery.trim()),
      limit: structured?.limit ?? 30,
    }
  }

  return { route, structured, reason: reasonParts.filter(Boolean).join(" | ") }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const CopilotState = Annotation.Root({
  userQuery: Annotation<string>(),
  workspacePath: Annotation<string>(),
  route: Annotation<CopilotSearchRoute>(),
  structuredPlan: Annotation<StructuredSearchPlan | null>(),
  analysisNotes: Annotation<string>(),
  semanticJson: Annotation<string>(),
  structuredJson: Annotation<string>(),
  finalAnswer: Annotation<string>(),
  trace: Annotation<string[]>({
    reducer: (left, right) => left.concat(Array.isArray(right) ? right : [right]),
    default: () => [],
  }),
})

type S = typeof CopilotState.State

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

async function understand_query(state: S): Promise<Partial<typeof CopilotState.Update>> {
  const raw = await invokeLocalLlm([
    { role: "system", content: ROUTING_SYSTEM },
    {
      role: "user",
      content: `Classify this analyst message for vault access:\n"""${state.userQuery}"""`,
    },
  ])
  const parsed = parseRoutingJson(raw)
  const decision = mergeRoutingHeuristics(state.userQuery, parsed)
  return {
    route: decision.route,
    structuredPlan: decision.structured,
    analysisNotes: decision.reason,
    trace: [
      `[understand_query] model_raw=${raw.slice(0, 280)}${raw.length > 280 ? "…" : ""}`,
      `[understand_query] route=${decision.route}`,
    ],
  }
}

export type SemanticThreatHit = {
  score: number
  sqliteRowid: number
  iocValue: string
  iocType: string
  firstSeen?: string | null
  lastSeen?: string | null
  sourceProject?: string | null
  metadata?: string | null
}

async function tool_semantic_search(state: S): Promise<Partial<typeof CopilotState.Update>> {
  try {
    const hits = await invoke<SemanticThreatHit[]>("semantic_threat_search", {
      query: state.userQuery,
    })
    const json = JSON.stringify(hits ?? [])
    return {
      semanticJson: json,
      trace: [`[tool_semantic_search] hits=${Array.isArray(hits) ? hits.length : 0}`],
    }
  } catch (e) {
    const err = JSON.stringify({ error: String(e) })
    return {
      semanticJson: err,
      trace: [`[tool_semantic_search] error`],
    }
  }
}

function buildStructuredParams(state: S): SearchVaultParams {
  const plan = state.structuredPlan
  const entity: SearchVaultEntity = plan?.entity ?? "iocRecords"
  const params: SearchVaultParams = {
    workspacePath: state.workspacePath,
    entity,
    limit: plan?.limit != null && Number.isFinite(plan.limit) ? Math.min(50, Math.max(1, plan.limit)) : 30,
  }
  if (plan?.textContains?.trim()) params.textContains = plan.textContains.trim()
  if (plan?.iocType?.trim()) params.iocType = plan.iocType.trim()
  if (plan?.threatActor?.trim()) params.threatActor = plan.threatActor.trim()
  if (plan?.sourceProject?.trim()) params.sourceProject = plan.sourceProject.trim()
  if (plan?.cveIdPrefix?.trim()) params.cveIdPrefix = plan.cveIdPrefix.trim()
  if (plan?.order === "recentFirst" || plan?.order === "oldestFirst") params.order = plan.order
  if (plan?.dateRange && typeof plan.dateRange === "object") params.dateRange = plan.dateRange
  if (plan?.minCvss != null && Number.isFinite(plan.minCvss)) params.minCvss = plan.minCvss
  if (plan?.maxCvss != null && Number.isFinite(plan.maxCvss)) params.maxCvss = plan.maxCvss
  if (!params.textContains && entity === "iocRecords") {
    params.textContains = state.userQuery.trim()
  }
  return params
}

async function tool_structured_search(state: S): Promise<Partial<typeof CopilotState.Update>> {
  try {
    const params = buildStructuredParams(state)
    const rows = await invokeSearchVault(params)
    return {
      structuredJson: JSON.stringify(rows),
      trace: [`[tool_structured_search] entity=${params.entity} rows=${rows.length}`],
    }
  } catch (e) {
    return {
      structuredJson: JSON.stringify({ error: String(e) }),
      trace: [`[tool_structured_search] error`],
    }
  }
}

async function tool_both_searches(state: S): Promise<Partial<typeof CopilotState.Update>> {
  const a = await tool_semantic_search(state)
  const b = await tool_structured_search(state)
  return {
    semanticJson: a.semanticJson ?? state.semanticJson,
    structuredJson: b.structuredJson ?? state.structuredJson,
    trace: ["[tool_both_searches] semantic + structured complete"],
  }
}

const SYNTH_SYSTEM = `You are Barney (CTI Command Center) in the synthesis step.
You receive JSON tool payloads from (1) semantic vector search over IOC embeddings and/or (2) structured SQLite vault search.
Produce a concise, accurate answer for a security analyst. If a tool returned an error object, say so briefly.
Do not invent IOCs or CVEs not present in the JSON. Use markdown sparingly (bullets OK).`

async function synthesize_answer(state: S): Promise<Partial<typeof CopilotState.Update>> {
  const userBlock = [
    `User question:\n${state.userQuery}`,
    `Routing notes: ${state.analysisNotes}`,
    `Semantic vector hits (JSON):\n${state.semanticJson || "[]"}`,
    `Structured vault rows (JSON):\n${state.structuredJson || "[]"}`,
  ].join("\n\n")

  const text = await invokeLocalLlm([
    { role: "system", content: SYNTH_SYSTEM },
    { role: "user", content: userBlock },
  ])
  return {
    finalAnswer: text || "(empty synthesis)",
    trace: ["[synthesize_answer] done"],
  }
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

function routeAfterUnderstand(state: S): CopilotSearchRoute {
  return state.route
}

/**
 * Full LangGraph definition: understand → tools (branch) → synthesize.
 * Compile once; reuse via {@link getCopilotInvestigationGraph}.
 */
export function buildCopilotInvestigationGraph() {
  const g = new StateGraph(CopilotState)
    .addNode("understand_query", understand_query)
    .addNode("tool_semantic_search", tool_semantic_search)
    .addNode("tool_structured_search", tool_structured_search)
    .addNode("tool_both_searches", tool_both_searches)
    .addNode("synthesize_answer", synthesize_answer)
    .addEdge(START, "understand_query")
    .addConditionalEdges("understand_query", routeAfterUnderstand, {
      semantic: "tool_semantic_search",
      structured: "tool_structured_search",
      both: "tool_both_searches",
      direct: "synthesize_answer",
    })
    .addEdge("tool_semantic_search", "synthesize_answer")
    .addEdge("tool_structured_search", "synthesize_answer")
    .addEdge("tool_both_searches", "synthesize_answer")
    .addEdge("synthesize_answer", END)

  return g
}

let _compiled: ReturnType<ReturnType<typeof buildCopilotInvestigationGraph>["compile"]> | null = null

export function getCopilotInvestigationGraph() {
  if (!_compiled) {
    _compiled = buildCopilotInvestigationGraph().compile({ name: "cti_copilot_investigation" })
  }
  return _compiled
}

export type CopilotGraphResult = typeof CopilotState.State

/**
 * Run the investigation copilot LangGraph once (embed → vector / vault → synthesis).
 */
export async function runCopilotInvestigationGraph(
  workspacePath: string,
  userQuery: string
): Promise<CopilotGraphResult> {
  const graph = getCopilotInvestigationGraph()
  const initial: typeof CopilotState.State = {
    userQuery: userQuery.trim(),
    workspacePath,
    route: "direct",
    structuredPlan: null,
    analysisNotes: "",
    semanticJson: "",
    structuredJson: "",
    finalAnswer: "",
    trace: [],
  }
  return graph.invoke(initial) as Promise<CopilotGraphResult>
}
