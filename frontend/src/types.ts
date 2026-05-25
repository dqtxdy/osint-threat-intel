export type Overview = {
  window_days: number;
  counts: {
    documents: number;
    entities: number;
    sources: number;
    source_types: number;
    languages: number;
    critical_priorities: number;
    high_priorities: number;
  };
  source_names: string[];
  source_types: string[];
  confirmation_matrix: Record<string, number>;
  source_coverage: SourceCoverage;
  top_priorities: PriorityFinding[];
  top_trends: TrendSignal[];
};

export type DistributionItem = {
  name: string;
  count: number;
  share: number;
};

export type SourceCoverage = {
  window_days: number;
  score: number;
  posture: string;
  documents: number;
  sources: number;
  source_types: number;
  languages: number;
  social_documents: number;
  trusted_documents: number;
  source_mix: Array<{
    source_id: string;
    source_name: string;
    source_type: string;
    language: string;
    documents: number;
    last_seen: string | null;
    reliability: string;
  }>;
  type_mix: DistributionItem[];
  language_mix: DistributionItem[];
  gaps: string[];
  recommendations: string[];
};

export type Health = {
  status: string;
  db_path: string;
  llm_provider: string;
  llm_model: string;
  llm_configured: boolean;
};

export type AttackLayer = {
  name: string;
  techniques: Array<{
    techniqueID: string;
    score: number;
    comment: string;
    enabled: boolean;
    metadata: Array<{ name: string; value: string }>;
  }>;
  [key: string]: unknown;
};

export type DocumentItem = {
  id: number;
  source_id: string;
  source_name: string;
  source_type: string;
  url: string;
  title: string;
  body: string;
  language: string | null;
  published_at: string | null;
  collected_at: string;
};

export type Enrichment = {
  provider: string;
  payload: Record<string, unknown>;
  enriched_at: string;
};

export type PriorityFinding = {
  entity_type: string;
  value: string;
  score: number;
  priority: "critical" | "high" | "medium" | "low";
  confirmation: string;
  mentions: number;
  source_count: number;
  source_reliability: string;
  analyst_verdict: string;
  first_seen: string | null;
  last_seen: string | null;
  rationale: string[];
  recommended_actions: string[];
  evidence_documents: Array<{
    id: number;
    source_name: string;
    source_type: string;
    title: string;
    url: string;
    published_at: string | null;
  }>;
  enrichments: Enrichment[];
};

export type TrendSignal = {
  type: string;
  value: string;
  mentions: number;
  source_count: number;
  social_mentions: number;
  non_social_mentions: number;
  first_seen: string | null;
  last_seen: string | null;
  confirmation: string;
  enrichments: Enrichment[];
};

export type EntitySummary = {
  type: string;
  value: string;
  mentions: number;
};

export type EntityDetail = {
  type: string;
  value: string;
  documents: DocumentItem[];
  enrichments: Enrichment[];
  co_occurring: Array<{ type: string; value: string; shared_documents: number }>;
  timeline: Array<{ day: string; mentions: number; source_count: number }>;
};

export type GraphData = {
  nodes: Array<{ id: string; label: string; type: string }>;
  edges: Array<{ source: string; target: string; label: string }>;
};
