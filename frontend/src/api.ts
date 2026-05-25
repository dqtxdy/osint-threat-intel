import type { AttackLayer, DocumentItem, EntityDetail, EntitySummary, GraphData, Health, Overview, PriorityFinding, SourceCoverage, TrendSignal } from "./types";

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
  trends: (days: number) => getJson<TrendSignal[]>(`/api/trends?days=${days}&limit=100`),
  report: (days: number) => getText(`/api/report?days=${days}`),
  detections: (days: number) => getText(`/api/detections?days=${days}`),
  attackLayer: (days: number) => getJson<AttackLayer>(`/api/attack-layer?days=${days}`),
  stix: (days: number) => getJson<Record<string, unknown>>(`/api/export-stix?days=${days}`),
  intelligencePack: (days: number) => getJson<Record<string, unknown>>(`/api/export-pack?days=${days}`),
  geminiReport: async (days: number) => {
    const response = await fetch(`${API_BASE}/api/gemini-report?days=${days}`, { method: "POST" });
    if (!response.ok) throw new Error(await response.text());
    return response.text();
  },
  runPipeline: async (days: number) => {
    const response = await fetch(`${API_BASE}/api/run-pipeline?days=${days}&source=all`, { method: "POST" });
    if (!response.ok) throw new Error(await response.text());
    return response.json() as Promise<Record<string, unknown>>;
  },
};
