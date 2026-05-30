import type { AttackLayer, DocumentItem, EntityDetail, EntitySummary, GraphData, Health, Overview, PriorityFinding, SourceCoverage, TrendSignal, SemanticGraphResponse } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

async function getText(path: string): Promise<string> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.text();
}

export const api = {
  health: () => getJson<Health>("/api/health"),
  overview: (days: number) => getJson<Overview>(`/api/overview?days=${days}`),
  sourceCoverage: (days: number) => getJson<SourceCoverage>(`/api/source-coverage?days=${days}`),
  priorities: (days: number) => getJson<PriorityFinding[]>(`/api/priorities?days=${days}&limit=25`),
  documents: (days: number) => getJson<DocumentItem[]>(`/api/documents?days=${days}`),
  entities: () => getJson<EntitySummary[]>("/api/entities?limit=200"),
  entityDetail: (type: string, value: string, days: number) =>
    getJson<EntityDetail>(`/api/entities/${encodeURIComponent(type)}/${encodeURIComponent(value)}?days=${days}`),
  entityGraph: (type: string, value: string) =>
    getJson<GraphData>(`/api/entities/${encodeURIComponent(type)}/${encodeURIComponent(value)}/graph`),
  entitySemanticGraph: (type: string, value: string) =>
    getJson<SemanticGraphResponse>(`/api/entities/${encodeURIComponent(type)}/${encodeURIComponent(value)}/semantic-graph`),
  trends: (days: number) => getJson<TrendSignal[]>(`/api/trends?days=${days}&limit=100`),
  report: (days: number, options?: { category?: string; entityType?: string; value?: string }) => {
    const params = new URLSearchParams({ days: String(days) });
    if (options?.category) params.set("category", options.category);
    if (options?.entityType) params.set("entity_type", options.entityType);
    if (options?.value) params.set("value", options.value);
    return getText(`/api/report?${params.toString()}`);
  },
  detections: (days: number, options?: { entityTypes?: string; category?: string; product?: string; minPriority?: string; limit?: number }) => {
    const params = new URLSearchParams({ days: String(days) });
    if (options?.entityTypes) params.set("entity_types", options.entityTypes);
    if (options?.category) params.set("category", options.category);
    if (options?.product) params.set("product", options.product);
    if (options?.minPriority) params.set("min_priority", options.minPriority);
    if (options?.limit) params.set("limit", String(options.limit));
    return getText(`/api/detections?${params.toString()}`);
  },
  attackLayer: (days: number) => getJson<AttackLayer>(`/api/attack-layer?days=${days}`),
  stix: (days: number) => getJson<Record<string, unknown>>(`/api/export-stix?days=${days}`),
  intelligencePack: (days: number) => getJson<Record<string, unknown>>(`/api/export-pack?days=${days}`),
  geminiReport: async (days: number) => {
    const response = await fetch(`${API_BASE}/api/gemini-report?days=${days}`, { method: "POST" });
    if (!response.ok) throw new Error(await response.text());
    return response.text();
  },
  chat: async (messages: Array<{ role: string; content: string }>, days: number) => {
    const response = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages, days }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json() as Promise<{
      answer: string;
      citations: Array<{ document_id: number; title: string; source_name: string; url: string }>;
      related_entities: Array<{ type: string; value: string }>;
      suggested_followups: string[];
      caveats: string[];
    }>;
  },
  runPipeline: async (days: number) => {
    const response = await fetch(`${API_BASE}/api/run-pipeline?days=${days}&source=all&live_only=true&fresh=false&enrich_limit=8`, { method: "POST" });
    if (!response.ok) throw new Error(await response.text());
    return response.json() as Promise<Record<string, unknown>>;
  },
};
