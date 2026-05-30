import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  Brain,
  Download,
  ExternalLink,
  FileText,
  GitBranch,
  Globe2,
  Layers3,
  Languages,
  Play,
  Radar,
  Search,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ElementType, ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "./api";
import type { AttackLayer, DocumentItem, EntityDetail, EntitySummary, GraphData, GraphEdge, GraphNode, Health, Overview, PriorityFinding, SourceCoverage, TrendSignal, SemanticGraphResponse, SemanticTriple } from "./types";

type Page = "overview" | "chat" | "coverage" | "priorities" | "feed" | "workbench" | "graph" | "attack" | "detections" | "reports" | "exports" | "pipeline";

const DAYS = 3650;
const CHART_GRID = "#dbe4ef";
const CHART_TICK = { fill: "#475569", fontSize: 11 };
const TOOLTIP_STYLE = {
  background: "#ffffff",
  border: "1px solid #d8e0ea",
  color: "#0f172a",
  boxShadow: "0 16px 35px rgba(15,23,42,0.12)",
};

const navItems: Array<{ id: Page; label: string; icon: React.ElementType }> = [
  { id: "overview", label: "Mission Control", icon: Radar },
  { id: "chat", label: "Analyst Chat", icon: Brain },
  { id: "coverage", label: "OSINT Coverage", icon: BarChart3 },
  { id: "priorities", label: "Priority Queue", icon: ShieldAlert },
  { id: "feed", label: "Threat Feed", icon: Globe2 },
  { id: "workbench", label: "Entity Workbench", icon: Boxes },
  { id: "graph", label: "Knowledge Graph", icon: GitBranch },
  { id: "attack", label: "ATT&CK Coverage", icon: Layers3 },
  { id: "detections", label: "Detection Builder", icon: TerminalSquare },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "exports", label: "Exports", icon: Download },
  { id: "pipeline", label: "Pipeline Status", icon: Activity },
];

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [priorities, setPriorities] = useState<PriorityFinding[]>([]);
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [entities, setEntities] = useState<EntitySummary[]>([]);
  const [trends, setTrends] = useState<TrendSignal[]>([]);
  const [selectedEntity, setSelectedEntity] = useState<EntitySummary | null>(null);
  const [entityDetail, setEntityDetail] = useState<EntityDetail | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [semanticGraph, setSemanticGraph] = useState<SemanticGraphResponse | null>(null);
  const [report, setReport] = useState("");
  const [detections, setDetections] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [attackLayer, setAttackLayer] = useState<AttackLayer | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [graphLoading, setGraphLoading] = useState(false);

  const [chatMessages, setChatMessages] = useState<Array<{ role: "user" | "assistant"; content: string }>>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState("");
  const [chatCitations, setChatCitations] = useState<Array<{ document_id: number; title: string; source_name: string; url: string }>>([]);
  const [chatCaveats, setChatCaveats] = useState<string[]>([]);
  const [chatRelatedEntities, setChatRelatedEntities] = useState<Array<{ type: string; value: string }>>([]);

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (!selectedEntity && entities.length) {
      setSelectedEntity(entities[0]);
    }
  }, [entities, selectedEntity]);

  useEffect(() => {
    if (!selectedEntity) return;
    setSemanticGraph(null);
    setGraph(null);
    setGraphLoading(true);
    
    Promise.all([
      api.entityDetail(selectedEntity.type, selectedEntity.value, DAYS).then(setEntityDetail),
      api.entityGraph(selectedEntity.type, selectedEntity.value).then(setGraph),
      api.entitySemanticGraph(selectedEntity.type, selectedEntity.value).then(setSemanticGraph)
    ])
      .catch((error) => setNotice(String(error)))
      .finally(() => setGraphLoading(false));
  }, [selectedEntity]);

  async function refresh() {
    setLoading(true);
    try {
      const [healthData, overviewData, priorityData, documentData, entityData, trendData, reportText, detectionText, attackData] = await Promise.all([
        api.health(),
        api.overview(DAYS),
        api.priorities(DAYS),
        api.documents(DAYS),
        api.entities(),
        api.trends(DAYS),
        api.report(DAYS),
        api.detections(DAYS),
        api.attackLayer(DAYS),
      ]);
      setHealth(healthData);
      setOverview(overviewData);
      setPriorities(priorityData);
      setDocuments(documentData);
      setEntities(entityData);
      setTrends(trendData);
      setReport(reportText);
      setDetections(detectionText);
      setAttackLayer(attackData);
      setNotice("");
    } catch (error) {
      setNotice(String(error));
    } finally {
      setLoading(false);
    }
  }

  async function handleSendPrompt(text: string) {
    if (!text.trim() || chatLoading) return;
    const newMessages = [...chatMessages, { role: "user" as const, content: text }];
    setChatMessages(newMessages);
    setChatInput("");
    setChatLoading(true);
    setChatError("");
    try {
      const result = await api.chat(newMessages, DAYS);
      setChatMessages([...newMessages, { role: "assistant" as const, content: result.answer }]);
      setChatCitations(result.citations ?? []);
      setChatCaveats(result.caveats ?? []);
      setChatRelatedEntities(result.related_entities ?? []);
    } catch (err: any) {
      setChatError(err.message || String(err));
    } finally {
      setChatLoading(false);
    }
  }

  async function runPipeline() {
    setNotice("Live OSINT update running...");
    try {
      await api.runPipeline(DAYS);
      await refresh();
      setNotice("Live OSINT update complete.");
    } catch (error) {
      setNotice(String(error));
    }
  }

  return (
    <div className="min-h-screen text-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-line bg-ink/90 px-4 py-5 backdrop-blur lg:block">
        <div className="mb-8 flex items-center gap-3 px-2">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyanx/30 bg-cyanx/10">
            <Radar className="h-6 w-6 text-cyanx" />
          </div>
          <div>
            <div className="text-sm font-semibold uppercase tracking-[0.18em] text-cyanx">OSINT CTI</div>
            <div className="text-lg font-semibold">Command Center</div>
          </div>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition ${
                  active ? "bg-cyanx/15 text-white ring-1 ring-cyanx/30" : "text-slate-400 hover:bg-white/5 hover:text-slate-100"
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="absolute bottom-5 left-4 right-4 rounded-lg border border-line bg-panel p-4 text-xs text-slate-400">
          <div className="mb-2 flex items-center gap-2 font-medium text-slate-200">
            <Activity className="h-4 w-4 text-tealt" />
            Demo posture
          </div>
          <div>Evidence-bound intelligence, safe exports, reproducible fallbacks.</div>
        </div>
      </aside>

      <main className="lg:pl-72">
        <header className="sticky top-0 z-20 border-b border-line bg-ink/80 px-5 py-4 backdrop-blur">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="text-xs font-medium uppercase tracking-[0.22em] text-cyanx">Threat Intelligence Operations</div>
              <h1 className="mt-1 text-2xl font-semibold tracking-normal">{navItems.find((item) => item.id === page)?.label}</h1>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="blue">{DAYS}d window</Badge>
              <button onClick={refresh} className="rounded-lg border border-line bg-panel px-3 py-2 text-sm text-slate-200 hover:bg-panel2">
                Refresh
              </button>
              <button onClick={runPipeline} className="flex items-center gap-2 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300">
                <Play className="h-4 w-4" />
                Run Live Update
              </button>
            </div>
          </div>
          {notice ? <div className="mt-3 rounded-lg border border-amberx/30 bg-amberx/10 px-3 py-2 text-sm text-amber-100">{notice}</div> : null}
        </header>

        <section className="p-5">
          {loading ? (
            <div className="grid min-h-[60vh] place-items-center text-slate-400">Loading intelligence workspace...</div>
          ) : (
            <>
              {page === "overview" && overview && <OverviewPage overview={overview} trends={trends} />}
              {page === "chat" && (
                <ChatPage
                  messages={chatMessages}
                  input={chatInput}
                  setInput={setChatInput}
                  loading={chatLoading}
                  error={chatError}
                  citations={chatCitations}
                  caveats={chatCaveats}
                  relatedEntities={chatRelatedEntities}
                  llmConfigured={health?.llm_configured ?? false}
                  onSendPrompt={handleSendPrompt}
                  onClearChat={() => {
                    setChatMessages([]);
                    setChatCitations([]);
                    setChatCaveats([]);
                    setChatRelatedEntities([]);
                    setChatError("");
                  }}
                />
              )}
              {page === "coverage" && overview && <CoveragePage coverage={overview.source_coverage} />}
              {page === "priorities" && <PrioritiesPage priorities={priorities} />}
              {page === "feed" && <ThreatFeed documents={documents} />}
              {page === "workbench" && (
                <WorkbenchPage entities={entities} selected={selectedEntity} onSelect={setSelectedEntity} detail={entityDetail} />
              )}
              {page === "graph" && <GraphPage entities={entities} selected={selectedEntity} onSelect={setSelectedEntity} semanticGraph={semanticGraph} graphLoading={graphLoading} />}
              {page === "attack" && <AttackCoveragePage attackLayer={attackLayer} />}
              {page === "detections" && <DetectionBuilderPage detections={detections} />}
              {page === "reports" && <ReportsPage report={report} entities={entities} selectedEntity={selectedEntity} />}
              {page === "exports" && <ExportsPage report={report} detections={detections} />}
              {page === "pipeline" && <PipelineStatusPage health={health} overview={overview} onRun={runPipeline} />}
            </>
          )}
        </section>
      </main>
    </div>
  );
}

function OverviewPage({ overview, trends }: { overview: Overview; trends: TrendSignal[] }) {
  const confirmationData = Object.entries(overview.confirmation_matrix).map(([name, value]) => ({ name, value }));
  const trendData = trends.slice(0, 8).map((trend) => ({ name: trend.value, mentions: trend.mentions, sources: trend.source_count }));
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <Metric label="Documents" value={overview.counts.documents} icon={FileText} />
        <Metric label="Entities" value={overview.counts.entities} icon={Boxes} />
        <Metric label="Sources" value={overview.counts.sources} icon={Globe2} />
        <Metric label="Languages" value={overview.counts.languages} icon={Languages} />
        <Metric label="Critical" value={overview.counts.critical_priorities} icon={AlertTriangle} tone="red" />
        <Metric label="High" value={overview.counts.high_priorities} icon={ShieldAlert} tone="amber" />
      </div>
      <div className="grid gap-5 xl:grid-cols-3">
        <Panel title="Top Priority Signals" className="xl:col-span-2">
          <div className="space-y-3">
            {overview.top_priorities.map((finding) => (
              <PriorityRow key={`${finding.entity_type}-${finding.value}`} finding={finding} compact />
            ))}
          </div>
        </Panel>
        <Panel title="Corroboration Matrix">
          <div className="h-64">
              <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <BarChart data={confirmationData}>
                <CartesianGrid stroke={CHART_GRID} />
                <XAxis dataKey="name" tick={CHART_TICK} />
                <YAxis tick={CHART_TICK} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {confirmationData.map((_, index) => <Cell key={index} fill={["#0f766e", "#0369a1", "#b45309"][index % 3]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>
      <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
        <Panel title="OSINT Coverage Posture">
          <div className="flex items-end justify-between gap-4">
            <div>
              <div className="text-5xl font-semibold text-white">{overview.source_coverage.score}</div>
              <div className="mt-1 text-sm uppercase tracking-wide text-slate-500">{overview.source_coverage.posture}</div>
            </div>
            <Badge tone={postureTone(overview.source_coverage.posture)}>
              {overview.source_coverage.sources} sources / {overview.source_coverage.source_types} types
            </Badge>
          </div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-ink">
            <div className="h-full rounded-full bg-cyanx" style={{ width: `${overview.source_coverage.score}%` }} />
          </div>
        </Panel>
        <Panel title="Source Type Mix">
          <div className="grid gap-3 sm:grid-cols-3">
            {overview.source_coverage.type_mix.map((item) => (
              <div key={item.name} className="rounded-lg border border-line bg-ink/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge tone={sourceTypeTone(item.name)}>{item.name}</Badge>
                  <span className="text-lg font-semibold text-slate-100">{item.count}</span>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink">
                  <div className="h-full rounded-full bg-tealt" style={{ width: `${item.share * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="Trending Entities">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
            <BarChart data={trendData}>
              <CartesianGrid stroke={CHART_GRID} />
              <XAxis dataKey="name" tick={CHART_TICK} />
              <YAxis tick={CHART_TICK} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="mentions" fill="#0369a1" radius={[6, 6, 0, 0]} />
              <Bar dataKey="sources" fill="#0f766e" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>
    </div>
  );
}

function CoveragePage({ coverage }: { coverage: SourceCoverage }) {
  const typeData = coverage.type_mix.map((item) => ({ name: item.name, count: item.count }));
  const languageData = coverage.language_mix.map((item) => ({ name: item.name, count: item.count }));
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <Metric label="Coverage Score" value={coverage.score} icon={BarChart3} tone={coverage.score >= 70 ? "green" : coverage.score >= 50 ? "amber" : "red"} />
        <Metric label="Documents" value={coverage.documents} icon={FileText} />
        <Metric label="Sources" value={coverage.sources} icon={Globe2} />
        <Metric label="Source Types" value={coverage.source_types} icon={Boxes} />
        <Metric label="Languages" value={coverage.languages} icon={Languages} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
        <Panel title="Source Reliability Matrix">
          <div className="overflow-hidden rounded-lg border border-line">
            <table className="w-full border-collapse text-sm">
              <thead className="bg-panel2 text-left text-xs uppercase tracking-wide text-slate-400">
                <tr>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Language</th>
                  <th className="px-4 py-3">Docs</th>
                  <th className="px-4 py-3">Reliability</th>
                  <th className="px-4 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {coverage.source_mix.map((source) => (
                  <tr key={source.source_id} className="border-t border-line/70 hover:bg-white/[0.03]">
                    <td className="px-4 py-3 font-medium text-slate-100">{source.source_name}</td>
                    <td className="px-4 py-3"><Badge tone={sourceTypeTone(source.source_type)}>{source.source_type}</Badge></td>
                    <td className="px-4 py-3 text-slate-300">{source.language}</td>
                    <td className="px-4 py-3 text-slate-300">{source.documents}</td>
                    <td className="px-4 py-3"><Badge tone={reliabilityTone(source.reliability)}>{source.reliability}</Badge></td>
                    <td className="px-4 py-3 text-slate-400">{formatDate(source.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Language Diversity">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <BarChart data={languageData}>
                <CartesianGrid stroke={CHART_GRID} />
                <XAxis dataKey="name" tick={CHART_TICK} />
                <YAxis tick={CHART_TICK} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#0f766e" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {coverage.language_mix.map((item) => (
              <Badge key={item.name} tone="blue">{item.name}: {percentage(item.share)}</Badge>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
        <Panel title="Source Category Distribution">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <BarChart data={typeData}>
                <CartesianGrid stroke={CHART_GRID} />
                <XAxis dataKey="name" tick={CHART_TICK} />
                <YAxis tick={CHART_TICK} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {typeData.map((_, index) => <Cell key={index} fill={["#0369a1", "#0f766e", "#b45309", "#dc2626"][index % 4]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <div className="grid gap-5 md:grid-cols-2">
          <Panel title="Coverage Gaps">
            <SectionList items={coverage.gaps.length ? coverage.gaps : ["No major coverage gaps detected."]} />
          </Panel>
          <Panel title="Collection Moves">
            <SectionList items={coverage.recommendations} />
          </Panel>
        </div>
      </div>
    </div>
  );
}

function PrioritiesPage({ priorities }: { priorities: PriorityFinding[] }) {
  const [active, setActive] = useState<PriorityFinding | null>(priorities[0] ?? null);
  useEffect(() => {
    if (!priorities.length) {
      setActive(null);
      return;
    }
    if (!active || !priorities.some((finding) => finding.entity_type === active.entity_type && finding.value === active.value)) {
      setActive(priorities[0]);
    }
  }, [priorities, active]);

  return (
    <div className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
      <Panel title="Explainable Priority Queue">
        <div className="space-y-3">
          {priorities.map((finding) => (
            <button key={`${finding.entity_type}-${finding.value}`} onClick={() => setActive(finding)} className="w-full text-left">
              <PriorityRow finding={finding} />
            </button>
          ))}
        </div>
      </Panel>
      <Panel title="Evidence And Actions">
        {active ? (
          <div className="space-y-5">
            <div>
              <div className="mb-2 flex items-center gap-2">
                <PriorityBadge priority={active.priority} />
                <span className="text-2xl font-semibold">{active.score}</span>
              </div>
              <h2 className="text-xl font-semibold">{active.value}</h2>
              <p className="mt-1 text-sm text-slate-400">{active.confirmation}</p>
            </div>
            <div className="grid gap-3 border-y border-line py-3 sm:grid-cols-3">
              <DecisionMetric label="Verdict" value={active.analyst_verdict} tone={verdictTone(active.analyst_verdict)} />
              <DecisionMetric label="Reliability" value={active.source_reliability} tone={reliabilityTone(active.source_reliability)} />
              <DecisionMetric label="Evidence" value={`${active.mentions} mentions / ${active.source_count} sources`} tone="blue" />
            </div>
            <SectionList title="Rationale" items={active.rationale} />
            <SectionList title="Recommended Actions" items={active.recommended_actions} />
            <div>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Evidence</h3>
              <div className="space-y-2">
                {active.evidence_documents.map((doc) => (
                  <a key={doc.id} href={doc.url} target="_blank" rel="noreferrer" className="block rounded-lg border border-line bg-ink/40 p-3 hover:border-cyanx/40">
                    <div className="text-sm font-medium text-slate-100">{doc.title}</div>
                    <div className="mt-1 text-xs text-slate-400">{doc.source_name}</div>
                  </a>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

function ThreatFeed({ documents }: { documents: DocumentItem[] }) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return documents.filter((doc) => `${doc.title} ${doc.body} ${doc.source_name}`.toLowerCase().includes(q));
  }, [documents, query]);
  return (
    <Panel title="Collected OSINT Documents">
      <div className="mb-4 flex items-center gap-2 rounded-lg border border-line bg-ink/50 px-3 py-2">
        <Search className="h-4 w-4 text-slate-500" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} className="w-full bg-transparent text-sm outline-none" placeholder="Search source, title, or body" />
      </div>
      <div className="overflow-hidden rounded-lg border border-line">
        <table className="w-full border-collapse text-sm">
          <thead className="bg-panel2 text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Published</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((doc) => (
              <tr key={doc.id} className="border-t border-line/70 hover:bg-white/[0.03]">
                <td className="px-4 py-3 text-slate-300">{doc.source_name}</td>
                <td className="px-4 py-3">
                  <a href={doc.url} target="_blank" rel="noreferrer" className="font-medium text-slate-100 hover:text-cyanx">
                    {doc.title}
                  </a>
                </td>
                <td className="px-4 py-3"><Badge>{doc.source_type}</Badge></td>
                <td className="px-4 py-3 text-slate-400">{formatDate(doc.published_at ?? doc.collected_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function WorkbenchPage({
  entities,
  selected,
  onSelect,
  detail,
}: {
  entities: EntitySummary[];
  selected: EntitySummary | null;
  onSelect: (entity: EntitySummary) => void;
  detail: EntityDetail | null;
}) {
  return (
    <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
      <Panel title="Entity Index">
        <div className="max-h-[70vh] space-y-2 overflow-y-auto pr-1 scrollbar-thin">
          {entities.map((entity) => (
            <button
              key={`${entity.type}-${entity.value}`}
              onClick={() => onSelect(entity)}
              className={`w-full rounded-lg border px-3 py-2 text-left text-sm ${
                selected?.type === entity.type && selected.value === entity.value ? "border-cyanx/50 bg-cyanx/10" : "border-line bg-ink/30 hover:bg-white/[0.03]"
              }`}
            >
              <div className="font-medium text-slate-100">{entity.value}</div>
              <div className="mt-1 flex items-center justify-between text-xs text-slate-400">
                <span>{entity.type}</span>
                <span>{entity.mentions} mentions</span>
              </div>
            </button>
          ))}
        </div>
      </Panel>
      <Panel title="Entity Profile">
        {detail ? (
          <div className="space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <Badge tone="blue">{detail.type}</Badge>
                <h2 className="mt-2 text-2xl font-semibold">{detail.value}</h2>
              </div>
              <Badge tone="green">{detail.documents.length} evidence docs</Badge>
            </div>
            {detail.timeline.length ? (
              <div className="h-56 rounded-lg border border-line bg-ink/30 p-3">
                <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
                  <LineChart data={detail.timeline}>
                    <CartesianGrid stroke={CHART_GRID} />
                    <XAxis dataKey="day" tick={CHART_TICK} />
                    <YAxis tick={CHART_TICK} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Line type="monotone" dataKey="mentions" stroke="#0369a1" strokeWidth={2} />
                    <Line type="monotone" dataKey="source_count" stroke="#0f766e" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : null}
            <div className="grid gap-4 xl:grid-cols-2">
              <MiniPanel title="Enrichment">
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-300 scrollbar-thin">{JSON.stringify(detail.enrichments, null, 2)}</pre>
              </MiniPanel>
              <MiniPanel title="Co-Mentions">
                <div className="space-y-2">
                  {detail.co_occurring.map((entity) => (
                    <div key={`${entity.type}-${entity.value}`} className="flex items-center justify-between rounded-lg bg-ink/40 px-3 py-2 text-sm">
                      <span>{entity.value}</span>
                      <span className="text-xs text-slate-400">{entity.shared_documents} shared</span>
                    </div>
                  ))}
                </div>
              </MiniPanel>
            </div>
            <MiniPanel title="Evidence Documents">
              <div className="space-y-2">
                {detail.documents.map((doc) => (
                  <a key={doc.id} href={doc.url} target="_blank" rel="noreferrer" className="block rounded-lg border border-line bg-ink/40 p-3 hover:border-cyanx/40">
                    <div className="font-medium text-slate-100">{doc.title}</div>
                    <div className="mt-1 text-xs text-slate-400">{doc.source_name} · {formatDate(doc.published_at ?? doc.collected_at)}</div>
                    <p className="mt-2 line-clamp-2 text-sm text-slate-400">{doc.body}</p>
                  </a>
                ))}
              </div>
            </MiniPanel>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

function GraphPage({
  entities,
  selected,
  onSelect,
  semanticGraph,
  graphLoading,
}: {
  entities: EntitySummary[];
  selected: EntitySummary | null;
  onSelect: (entity: EntitySummary) => void;
  semanticGraph: SemanticGraphResponse | null;
  graphLoading: boolean;
}) {
  const [selectedLens, setSelectedLens] = useState<"risk" | "evidence" | "intel" | "triples" | "timeline">("risk");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedEntityTypes, setSelectedEntityTypes] = useState<string[]>([]);
  const [selectedRiskLevels, setSelectedRiskLevels] = useState<string[]>([]);
  const [hideNoise, setHideNoise] = useState<boolean>(true);
  const [groupLowSignal, setGroupLowSignal] = useState<boolean>(true);
  const [search, setSearch] = useState("");

  // Reset filters when the focused entity changes, to prevent stale filter states
  useEffect(() => {
    setSelectedCategories([]);
    setSelectedEntityTypes([]);
    setSelectedRiskLevels([]);
    setSearch("");
  }, [selected]);

  function isReferenceDomain(entityType: string, value: string): boolean {
    if (entityType !== "domain") return false;
    const val = value.toLowerCase().trim();
    const NOISE_DOMAINS = ["github.com", "cisa.gov", "mitre.org", "abuse.ch", "google.com", "microsoft.com", "nvd.nist.gov", "symfony.com", "bin.sh"];
    return NOISE_DOMAINS.some(domain => val === domain || val.endsWith("." + domain));
  }

  const { nodes: processedNodes, edges: processedEdges } = useMemo(() => {
    if (!semanticGraph) return { nodes: [], edges: [] };

    // 1. Filter Nodes
    const filteredNodes = semanticGraph.nodes.filter(node => {
      // Hide Noise toggle
      if (hideNoise) {
        const isNoise = node.badges?.includes("REFERENCE") || node.risk_level === "info" && isReferenceDomain(node.entity_type ?? "", node.value ?? "");
        if (isNoise && node.id !== "selected") return false;
      }

      // Lens filters
      if (selectedLens === "risk") {
        if (node.kind === "related_entity" && !["critical", "high", "medium"].includes(node.risk_level ?? "")) {
          return false;
        }
      } else if (selectedLens === "evidence") {
        if (node.kind === "related_entity") return false;
      } else if (selectedLens === "intel") {
        if (node.kind === "source" || node.kind === "document") return false;
      } else if (selectedLens === "timeline") {
        if (node.kind === "related_entity") return false;
      }

      // Entity Types Filter
      if (selectedEntityTypes.length > 0 && node.entity_type) {
        if (node.id !== "selected" && !selectedEntityTypes.includes(node.entity_type)) return false;
      }

      // Risk Levels Filter
      if (selectedRiskLevels.length > 0 && node.risk_level) {
        if (node.id !== "selected" && !selectedRiskLevels.includes(node.risk_level)) return false;
      }

      return true;
    });

    // 2. Filter Edges
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = semanticGraph.edges.filter(edge => {
      if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return false;

      // Lens edge category filters
      if (selectedLens === "risk") {
        if (!["vulnerability", "malware", "phishing", "structural"].includes(edge.category ?? "")) return false;
      } else if (selectedLens === "evidence") {
        if (!["structural", "general"].includes(edge.category ?? "") && edge.source !== "selected" && edge.target !== "selected") return false;
      } else if (selectedLens === "intel") {
        if (edge.category === "structural") return false;
      } else if (selectedLens === "timeline") {
        if (edge.category !== "structural") return false;
      }

      // Category Filter
      if (selectedCategories.length > 0 && edge.category) {
        if (!selectedCategories.includes(edge.category)) return false;
      }

      return true;
    });

    // Derive direct semantic edges in Related Intel lens to avoid orphaned nodes
    if (selectedLens === "intel") {
      const allDocs = semanticGraph.nodes.filter(n => n.kind === "document");
      const derivedEdges: GraphEdge[] = [];
      const derivedEdgeKeys = new Set<string>();

      filteredNodes.forEach(node => {
        if (node.id === "selected") return;

        // Find document nodes D that connect to both "selected" and `node`
        const connectingDocs = allDocs.filter(doc => {
          const connToSelected = semanticGraph.edges.some(e => 
            (e.source === "selected" && e.target === doc.id) ||
            (e.target === "selected" && e.source === doc.id)
          );
          const connToNode = semanticGraph.edges.some(e => 
            (e.source === node.id && e.target === doc.id) ||
            (e.target === node.id && e.source === doc.id)
          );
          return connToSelected && connToNode;
        });

        connectingDocs.forEach(doc => {
          const edgeToNode = semanticGraph.edges.find(e => 
            (e.source === doc.id && e.target === node.id) ||
            (e.target === doc.id && e.source === node.id)
          );
          if (edgeToNode && edgeToNode.category !== "structural") {
            if (selectedCategories.length > 0 && !selectedCategories.includes(edgeToNode.category ?? "")) return;
            const source = edgeToNode.source === node.id ? node.id : "selected";
            const target = edgeToNode.target === node.id ? node.id : "selected";
            const predicate = edgeToNode.predicate;
            const key = `${source}->${target}:${predicate}`;

            if (!derivedEdgeKeys.has(key) && !filteredEdges.some(fe => fe.source === source && fe.target === target && fe.predicate === predicate)) {
              derivedEdgeKeys.add(key);
              derivedEdges.push({
                id: key,
                source,
                target,
                predicate: edgeToNode.predicate,
                label: edgeToNode.label,
                category: edgeToNode.category,
                confidence: edgeToNode.confidence,
                source_reliability: edgeToNode.source_reliability,
                evidence_document_ids: edgeToNode.evidence_document_ids,
                evidence_count: edgeToNode.evidence_count,
                rationale: `Derived from: ${edgeToNode.rationale}`,
                first_seen: edgeToNode.first_seen,
                last_seen: edgeToNode.last_seen
              });
            }
          }
        });
      });
      filteredEdges.push(...derivedEdges);
    }

    // 3. Group low-signal nodes if they exceed 3
    const lowSignalNodes = filteredNodes.filter(n => 
      n.kind === "related_entity" && 
      (n.risk_level === "info" || n.risk_level === "low" || n.badges?.includes("REFERENCE") || isReferenceDomain(n.entity_type ?? "", n.value ?? ""))
    );

    if (groupLowSignal && lowSignalNodes.length > 3) {
      const nonGrouped = filteredNodes.filter(n => !lowSignalNodes.includes(n));
      const groupedId = "grouped-low-signal";
      const groupedNode: GraphNode = {
        id: groupedId,
        label: `${lowSignalNodes.length} Reference Domains`,
        kind: "related_entity",
        type: "grouped",
        risk_level: "info",
        badges: ["LOW SIGNAL", "REFERENCE"],
        description: `Collapsed reference domains (click individual nodes or toggle 'Hide Reference Nodes' off for detailed view):\n${lowSignalNodes.map(n => `• ${n.label} (${n.entity_type})`).join("\n")}`,
        confidence: 1.0,
        evidence_count: lowSignalNodes.reduce((acc, n) => acc + (n.evidence_count ?? 0), 0)
      };

      const remappedEdges = filteredEdges.map(edge => {
        const isSrcLow = lowSignalNodes.some(n => n.id === edge.source);
        const isTgtLow = lowSignalNodes.some(n => n.id === edge.target);
        if (isSrcLow || isTgtLow) {
          return {
            ...edge,
            source: isSrcLow ? groupedId : edge.source,
            target: isTgtLow ? groupedId : edge.target,
            label: "references domain",
            predicate: "REFERENCES_DOMAIN"
          };
        }
        return edge;
      });

      const seenKeys = new Set<string>();
      const finalEdges = remappedEdges.filter(edge => {
        const key = `${edge.source}->${edge.target}:${edge.predicate}`;
        if (seenKeys.has(key)) return false;
        seenKeys.add(key);
        return true;
      });

      return {
        nodes: [...nonGrouped, groupedNode],
        edges: finalEdges
      };
    }

    return { nodes: filteredNodes, edges: filteredEdges };
  }, [semanticGraph, selectedLens, selectedCategories, selectedEntityTypes, selectedRiskLevels, hideNoise, groupLowSignal]);

  const displayGraph = useMemo(() => ({
    nodes: processedNodes,
    edges: processedEdges
  }), [processedNodes, processedEdges]);

  const displayTriples = useMemo(() => {
    if (!semanticGraph) return [];
    
    const nodesByLabel = new Map<string, GraphNode>();
    semanticGraph.nodes.forEach(n => {
      nodesByLabel.set(n.label, n);
    });

    return semanticGraph.triples.filter(triple => {
      const subNode = nodesByLabel.get(triple.subject);
      const objNode = nodesByLabel.get(triple.object);
      
      const matchingEdge = semanticGraph.edges.find(e => 
        e.predicate === triple.predicate &&
        ((e.source === subNode?.id && e.target === objNode?.id) ||
         (subNode?.id === "selected" && e.source === "selected" && e.target === objNode?.id) ||
         (objNode?.id === "selected" && e.target === "selected" && e.source === subNode?.id))
      );

      // Filter by active search query
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesSearch = 
          triple.subject.toLowerCase().includes(q) ||
          triple.predicate.toLowerCase().includes(q) ||
          triple.object.toLowerCase().includes(q) ||
          triple.rationale.toLowerCase().includes(q);
        if (!matchesSearch) return false;
      }

      // Filter by category
      if (selectedCategories.length > 0) {
        if (!matchingEdge?.category || !selectedCategories.includes(matchingEdge.category)) {
          return false;
        }
      }

      // Filter by entity type
      if (selectedEntityTypes.length > 0) {
        const subType = subNode?.entity_type;
        const objType = objNode?.entity_type;
        const subMatch = subType && selectedEntityTypes.includes(subType);
        const objMatch = objType && selectedEntityTypes.includes(objType);
        if (!subMatch && !objMatch) return false;
      }

      // Filter by risk levels
      if (selectedRiskLevels.length > 0) {
        const subRisk = subNode?.risk_level;
        const objRisk = objNode?.risk_level;
        const subMatch = subRisk && selectedRiskLevels.includes(subRisk);
        const objMatch = objRisk && selectedRiskLevels.includes(objRisk);
        if (!subMatch && !objMatch) return false;
      }

      // Hide noise nodes if hideNoise is checked
      if (hideNoise) {
        const isNoiseSub = subNode && subNode.id !== "selected" && (subNode.badges?.includes("REFERENCE") || (subNode.risk_level === "info" && isReferenceDomain(subNode.entity_type ?? "", subNode.value ?? "")));
        const isNoiseObj = objNode && objNode.id !== "selected" && (objNode.badges?.includes("REFERENCE") || (objNode.risk_level === "info" && isReferenceDomain(objNode.entity_type ?? "", objNode.value ?? "")));
        if (isNoiseSub || isNoiseObj) {
          return false;
        }
      }

      return true;
    });
  }, [semanticGraph, search, selectedCategories, selectedEntityTypes, selectedRiskLevels, hideNoise]);

  function focusEntity(node: GraphNode) {
    if (!node.entity_type || !node.value) return;
    const existing = entities.find((item) => item.type === node.entity_type && item.value === node.value);
    onSelect(existing ?? { type: node.entity_type, value: node.value, mentions: node.evidence_count ?? 0 });
  }

  const evidenceDocsCount = processedNodes.filter(n => n.kind === "document").length;
  const relatedEntitiesCount = processedNodes.filter(n => n.kind === "related_entity").length;

  return (
    <div className="space-y-5 text-slate-100">
      {/* Analyst Takeaway & Summary Header */}
      {semanticGraph && (
        <Panel title="Analyst Summary Takeaway">
          <div className="space-y-3">
            <div className="text-sm font-medium leading-relaxed border-l-4 border-cyanx pl-3 bg-cyanx/5 py-2 rounded-r-lg text-slate-200">
              {semanticGraph.summary.analyst_takeaway}
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
              <span className="font-medium text-slate-300">
                Showing {semanticGraph.summary.displayed_evidence_count ?? semanticGraph.summary.evidence_count} of {semanticGraph.summary.total_evidence_count ?? semanticGraph.summary.evidence_count} evidence records
              </span>
              {semanticGraph.summary.aggregation_applied && (
                <Badge tone="amber">
                  {(semanticGraph.summary.displayed_evidence_count ?? semanticGraph.summary.evidence_count) ===
                  (semanticGraph.summary.total_evidence_count ?? semanticGraph.summary.evidence_count)
                    ? "Visual Grouping Active"
                    : "Aggregation Active"}
                </Badge>
              )}
            </div>
            
            {semanticGraph.summary.caveats.length > 0 && (
              <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-3 text-xs text-slate-300 space-y-1">
                <div className="font-semibold uppercase tracking-wider text-amberx">Caveats & Limitations:</div>
                <ul className="list-disc pl-4 space-y-1">
                  {semanticGraph.summary.caveats.map((caveat, idx) => (
                    <li key={idx}>{caveat}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Knowledge Graph Workbench">
        {/* Selected Entity Dropdown & Stats */}
        <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_auto] lg:items-center">
          <select
            value={selected ? `${selected.type}|${selected.value}` : ""}
            onChange={(event) => {
              const [type, value] = event.target.value.split("|");
              const entity = entities.find((item) => item.type === type && item.value === value);
              if (entity) onSelect(entity);
            }}
            className="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm text-slate-100"
          >
            {entities.map((entity) => (
              <option key={`${entity.type}-${entity.value}`} value={`${entity.type}|${entity.value}`}>
                {entity.type} · {entity.value}
              </option>
            ))}
          </select>
          <div className="flex flex-wrap gap-2">
            <Badge tone="blue">{evidenceDocsCount} evidence docs</Badge>
            <Badge tone="green">{relatedEntitiesCount} related entities</Badge>
            <Badge tone="amber">{processedEdges.length} semantic relationships</Badge>
          </div>
        </div>

        {/* Graph Lenses / Tabs */}
        <div className="flex border-b border-line mb-4">
          {(["risk", "evidence", "intel", "triples", "timeline"] as const).map((lens) => (
            <button
              key={lens}
              onClick={() => setSelectedLens(lens)}
              className={`px-4 py-2 text-sm font-semibold border-b-2 transition ${
                selectedLens === lens ? "border-cyanx text-cyanx font-bold" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              {lens === "risk" && "Risk Story"}
              {lens === "evidence" && "Evidence"}
              {lens === "intel" && "Related Intel"}
              {lens === "triples" && "Triples"}
              {lens === "timeline" && "Timeline / Sources"}
            </button>
          ))}
        </div>

        {/* Filter Controls Row */}
        {selectedLens !== "triples" && (
          <div className="bg-ink/20 p-3 rounded-lg border border-line mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            {/* Category Filter */}
            <div>
              <label className="block text-[10px] font-bold text-slate-400 mb-1 tracking-wider">RELATIONSHIP CATEGORY</label>
              <div className="flex flex-wrap gap-1">
                {semanticGraph?.filters.categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => {
                      setSelectedCategories(prev =>
                        prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
                      );
                    }}
                    className={`px-2 py-0.5 rounded text-[10px] border transition ${
                      selectedCategories.includes(cat)
                        ? "bg-cyanx/20 border-cyanx text-cyanx"
                        : "bg-ink border-line text-slate-400"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Entity Types Filter */}
            <div>
              <label className="block text-[10px] font-bold text-slate-400 mb-1 tracking-wider">ENTITY TYPES</label>
              <div className="flex flex-wrap gap-1">
                {semanticGraph?.filters.entity_types.map(type => (
                  <button
                    key={type}
                    onClick={() => {
                      setSelectedEntityTypes(prev =>
                        prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
                      );
                    }}
                    className={`px-2 py-0.5 rounded text-[10px] border transition ${
                      selectedEntityTypes.includes(type)
                        ? "bg-tealt/20 border-tealt text-tealt"
                        : "bg-ink border-line text-slate-400"
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* Severity / Risk Filter */}
            <div>
              <label className="block text-[10px] font-bold text-slate-400 mb-1 tracking-wider">SEVERITY / RISK</label>
              <div className="flex flex-wrap gap-1">
                {semanticGraph?.filters.risk_levels.map(risk => (
                  <button
                    key={risk}
                    onClick={() => {
                      setSelectedRiskLevels(prev =>
                        prev.includes(risk) ? prev.filter(r => r !== risk) : [...prev, risk]
                      );
                    }}
                    className={`px-2 py-0.5 rounded text-[10px] border transition ${
                      selectedRiskLevels.includes(risk)
                        ? "bg-danger/20 border-danger text-danger"
                        : "bg-ink border-line text-slate-400"
                    }`}
                  >
                    {risk}
                  </button>
                ))}
              </div>
            </div>

            {/* Toggles */}
            <div>
              <label className="flex items-center gap-2 text-xs font-semibold text-slate-200 cursor-pointer select-none mb-1">
                <input
                  type="checkbox"
                  checked={hideNoise}
                  onChange={(e) => setHideNoise(e.target.checked)}
                  className="rounded border-line bg-ink text-cyanx focus:ring-cyanx"
                />
                Hide Reference/Noise Nodes
              </label>
              <label className="flex items-center gap-2 text-xs font-semibold text-slate-200 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={groupLowSignal}
                  onChange={(e) => setGroupLowSignal(e.target.checked)}
                  className="rounded border-line bg-ink text-cyanx focus:ring-cyanx"
                />
                Group Low-Signal Nodes
              </label>
            </div>

            {/* Reset Action */}
            <div className="flex items-center lg:justify-end">
              <button
                onClick={() => {
                  setSelectedCategories([]);
                  setSelectedEntityTypes([]);
                  setSelectedRiskLevels([]);
                  setHideNoise(true);
                  setGroupLowSignal(true);
                  setSearch("");
                }}
                className="text-xs text-slate-500 hover:text-slate-300 underline"
              >
                Reset Filters
              </button>
            </div>
          </div>
        )}

        {/* Graph Render Area */}
        {graphLoading ? (
          <div className="py-20 flex flex-col items-center justify-center text-slate-400 gap-3">
            <div className="w-10 h-10 border-4 border-cyanx border-t-transparent rounded-full animate-spin"></div>
            <div className="text-sm font-semibold tracking-wide">Loading Semantic Graph 2.0...</div>
          </div>
        ) : semanticGraph ? (
          selectedLens === "triples" ? (
            <TriplesTable triples={displayTriples} search={search} setSearch={setSearch} />
          ) : displayGraph.edges.length === 0 ? (
            <div className="py-20 flex flex-col items-center justify-center text-slate-400 gap-2 border border-line rounded-xl bg-ink/20">
              <AlertTriangle className="h-8 w-8 text-amberx" />
              <div className="text-sm font-semibold text-slate-200">No Relationships Found</div>
              <div className="text-xs max-w-md text-center text-slate-400">
                No semantic relationships match the active lens, categories, or filters. Try resetting filters or choosing a different lens.
              </div>
              <button
                onClick={() => {
                  setSelectedCategories([]);
                  setSelectedEntityTypes([]);
                  setSelectedRiskLevels([]);
                  setHideNoise(true);
                  setGroupLowSignal(true);
                  setSearch("");
                }}
                className="mt-3 px-3 py-1.5 text-xs font-semibold rounded bg-cyanx text-ink hover:bg-sky-400 transition"
              >
                Reset All Filters
              </button>
            </div>
          ) : (
            <KnowledgeGraph
              graph={displayGraph}
              relationshipFilter={selectedLens}
              onRelationshipFilter={() => {}}
              onFocusEntity={focusEntity}
              semanticGraphResponse={semanticGraph}
            />
          )
        ) : (
          <div className="py-8 text-center text-slate-400">No semantic graph loaded.</div>
        )}
      </Panel>

      {/* Triples Table displayed below the graph workspace */}
      {semanticGraph && selectedLens !== "triples" && (
        <Panel title="Semantic Triples Feed">
          <TriplesTable triples={displayTriples} search={search} setSearch={setSearch} />
        </Panel>
      )}
    </div>
  );
}

function TriplesTable({ triples, search, setSearch }: { triples: SemanticTriple[]; search: string; setSearch: (s: string) => void }) {
  return (
    <div className="space-y-3 text-slate-100">
      <div className="flex items-center gap-2 rounded-lg border border-line bg-ink/50 px-3 py-2">
        <Search className="h-4 w-4 text-slate-500" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-transparent text-sm outline-none text-slate-100 placeholder-slate-400"
          placeholder="Filter triples by subject, predicate, object, or rationale..."
        />
      </div>
      <div className="overflow-hidden rounded-lg border border-line">
        <table className="w-full border-collapse text-sm">
          <thead className="bg-panel2 text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Subject</th>
              <th className="px-4 py-3">Predicate</th>
              <th className="px-4 py-3">Object</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Rationale</th>
            </tr>
          </thead>
          <tbody>
            {triples.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-400">
                  No triples match the current query.
                </td>
              </tr>
            ) : (
              triples.map((triple, index) => (
                <tr key={index} className="border-t border-line/70 hover:bg-white/[0.03]">
                  <td className="px-4 py-3 font-semibold text-slate-200">{triple.subject}</td>
                  <td className="px-4 py-3">
                    <Badge tone={relationshipTone(triple.predicate)}>{triple.predicate}</Badge>
                  </td>
                  <td className="px-4 py-3 font-semibold text-slate-200">{triple.object}</td>
                  <td className="px-4 py-3 text-slate-300">{(triple.confidence * 100).toFixed(0)}%</td>
                  <td className="px-4 py-3 text-slate-400">{triple.rationale}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReportsPage({ report, entities, selectedEntity }: { report: string; entities: EntitySummary[]; selectedEntity: EntitySummary | null }) {
  const [gemini, setGemini] = useState("");
  const [error, setError] = useState("");
  const [scopeMode, setScopeMode] = useState("malware");
  const entityTypes = useMemo(() => Array.from(new Set(entities.map((entity) => entity.type))).sort(), [entities]);
  const [entityType, setEntityType] = useState("");
  const [entityKey, setEntityKey] = useState("");
  const [scopedReport, setScopedReport] = useState("");
  const [scopeError, setScopeError] = useState("");

  useEffect(() => {
    if (!entityType && entityTypes.length) setEntityType(entityTypes[0]);
  }, [entityTypes, entityType]);

  useEffect(() => {
    if (!entityKey && selectedEntity) setEntityKey(`${selectedEntity.type}|${selectedEntity.value}`);
  }, [selectedEntity, entityKey]);

  async function generateGemini() {
    setError("");
    setGemini("Generating...");
    try {
      setGemini(await api.geminiReport(DAYS));
    } catch (err) {
      setGemini("");
      setError(String(err));
    }
  }

  async function generateScopedReport() {
    setScopeError("");
    setScopedReport("Generating...");
    try {
      if (scopeMode === "all") {
        setScopedReport(await api.report(DAYS));
      } else if (scopeMode === "entity_type") {
        setScopedReport(await api.report(DAYS, { entityType }));
      } else if (scopeMode === "entity") {
        const [type, value] = entityKey.split("|");
        setScopedReport(await api.report(DAYS, { entityType: type, value }));
      } else {
        setScopedReport(await api.report(DAYS, { category: scopeMode }));
      }
    } catch (err) {
      setScopedReport("");
      setScopeError(String(err));
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
      <div className="space-y-5">
        <Panel title="Focused Report Builder">
          <div className="space-y-3">
            <select value={scopeMode} onChange={(event) => setScopeMode(event.target.value)} className="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm">
              <option value="all">All Intelligence</option>
              <option value="vulnerabilities">Vulnerabilities & Exposure</option>
              <option value="malware">Malware, Ransomware & Indicators</option>
              <option value="attack">MITRE ATT&CK Techniques</option>
              <option value="vendors">Vendors & Products</option>
              <option value="entity_type">One Entity Type</option>
              <option value="entity">One Exact Entity</option>
            </select>
            {scopeMode === "entity_type" ? (
              <select value={entityType} onChange={(event) => setEntityType(event.target.value)} className="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm">
                {entityTypes.map((type) => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            ) : null}
            {scopeMode === "entity" ? (
              <select value={entityKey} onChange={(event) => setEntityKey(event.target.value)} className="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm">
                {entities.map((entity) => (
                  <option key={`${entity.type}|${entity.value}`} value={`${entity.type}|${entity.value}`}>
                    {entity.type} · {entity.value}
                  </option>
                ))}
              </select>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <button onClick={generateScopedReport} className="flex items-center gap-2 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300">
                <FileText className="h-4 w-4" />
                Generate Focused Report
              </button>
              {scopedReport ? (
                <button onClick={() => download("focused_report.md", scopedReport, "text/markdown")} className="rounded-lg border border-line bg-panel px-3 py-2 text-sm font-semibold text-slate-100 hover:bg-panel2">
                  Download
                </button>
              ) : null}
            </div>
            {scopeError ? <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-3 text-sm text-amber-100">{scopeError}</div> : null}
          </div>
        </Panel>
        <Panel title="Gemini Analyst Report">
          <button onClick={generateGemini} className="mb-4 flex items-center gap-2 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300">
            <Sparkles className="h-4 w-4" />
            Generate
          </button>
          {error ? <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-3 text-sm text-amber-100">{error}</div> : null}
          {gemini ? <pre className="max-h-[45vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-300 scrollbar-thin">{gemini}</pre> : null}
        </Panel>
      </div>
      <div className="space-y-5">
        {scopedReport ? (
          <Panel title="Focused Analyst Report">
            <pre className="max-h-[72vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-300 scrollbar-thin">{scopedReport}</pre>
          </Panel>
        ) : null}
        <Panel title="Global Analyst Report">
          <pre className="max-h-[72vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-300 scrollbar-thin">{report}</pre>
        </Panel>
      </div>
    </div>
  );
}

function AttackCoveragePage({ attackLayer }: { attackLayer: AttackLayer | null }) {
  const techniques = attackLayer?.techniques ?? [];
  const data = techniques.map((technique) => ({ id: technique.techniqueID, score: technique.score }));
  return (
    <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
      <Panel title="ATT&CK Technique Heat">
        {data.length ? (
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <BarChart data={data}>
                <CartesianGrid stroke={CHART_GRID} />
                <XAxis dataKey="id" tick={CHART_TICK} />
                <YAxis tick={CHART_TICK} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="score" fill="#0369a1" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="rounded-lg border border-line bg-ink/40 p-4 text-sm text-slate-400">No ATT&CK techniques extracted yet.</div>
        )}
        <div className="mt-4 space-y-2">
          {techniques.map((technique) => (
            <div key={technique.techniqueID} className="rounded-lg border border-line bg-ink/30 p-3">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-slate-100">{technique.techniqueID}</div>
                <Badge tone="blue">score {technique.score}</Badge>
              </div>
              <div className="mt-1 text-sm text-slate-400">{technique.comment}</div>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Navigator Layer JSON">
        <button
          onClick={() => download("attack_navigator_layer.json", JSON.stringify(attackLayer, null, 2), "application/json")}
          className="mb-4 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300"
        >
          Download Layer
        </button>
        <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300 scrollbar-thin">{JSON.stringify(attackLayer, null, 2)}</pre>
      </Panel>
    </div>
  );
}

function DetectionBuilderPage({ detections }: { detections: string }) {
  return (
    <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
      <Panel title="Safe Detection Builder">
        <div className="space-y-4 text-sm text-slate-300">
          <div className="rounded-lg border border-line bg-ink/40 p-4">
            Generates Sigma-style hunting stubs from prioritized CVEs, ATT&CK techniques, and indicators.
          </div>
          <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-4 text-amber-100">
            Rules are marked experimental and require tuning before operational use.
          </div>
          <button onClick={() => download("sigma_hunts.yml", detections, "text/yaml")} className="rounded-lg bg-cyanx px-3 py-2 font-semibold text-ink hover:bg-sky-300">
            Download Sigma Hunts
          </button>
        </div>
      </Panel>
      <Panel title="Sigma Hunting Preview">
        <pre className="max-h-[75vh] overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300 scrollbar-thin">{detections}</pre>
      </Panel>
    </div>
  );
}

function PipelineStatusPage({ health, overview, onRun }: { health: Health | null; overview: Overview | null; onRun: () => void }) {
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Runtime Status">
        <div className="space-y-3 text-sm">
          <StatusLine label="API" value={health?.status ?? "unknown"} />
          <StatusLine label="Database" value={health?.db_path ?? "unknown"} />
          <StatusLine label="LLM provider" value={health?.llm_provider ?? "unknown"} />
          <StatusLine label="LLM model" value={health?.llm_model ?? "unknown"} />
          <StatusLine label="LLM configured" value={health?.llm_configured ? "yes" : "no"} />
        </div>
        <button onClick={onRun} className="mt-5 flex items-center gap-2 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300">
          <Play className="h-4 w-4" />
          Run Live Update
        </button>
      </Panel>
      <Panel title="Current Data Coverage">
        {overview ? (
          <div className="space-y-3 text-sm">
            <StatusLine label="Documents" value={String(overview.counts.documents)} />
            <StatusLine label="Entities" value={String(overview.counts.entities)} />
            <StatusLine label="Sources" value={String(overview.counts.sources)} />
            <StatusLine label="Critical priorities" value={String(overview.counts.critical_priorities)} />
            <StatusLine label="Source names" value={overview.source_names.join(", ")} />
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

function ExportsPage({ report, detections }: { report: string; detections: string }) {
  async function downloadJson(name: string, loader: () => Promise<Record<string, unknown>>) {
    const data = await loader();
    download(name, JSON.stringify(data, null, 2), "application/json");
  }
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Export Center">
        <div className="grid gap-3 sm:grid-cols-2">
          <ExportButton icon={FileText} label="Markdown Report" onClick={() => download("latest_report.md", report, "text/markdown")} />
          <ExportButton icon={Boxes} label="Intelligence Pack" onClick={() => downloadJson("intelligence_pack.json", () => api.intelligencePack(DAYS))} />
          <ExportButton icon={ShieldAlert} label="Sigma Hunts" onClick={() => download("sigma_hunts.yml", detections, "text/yaml")} />
          <ExportButton icon={Layers3} label="ATT&CK Layer" onClick={() => downloadJson("attack_navigator_layer.json", () => api.attackLayer(DAYS))} />
          <ExportButton icon={Brain} label="STIX Bundle" onClick={() => downloadJson("stix_bundle.json", () => api.stix(DAYS))} />
        </div>
      </Panel>
      <Panel title="Detection Preview">
        <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300 scrollbar-thin">{detections}</pre>
      </Panel>
    </div>
  );
}

function StatusLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-lg border border-line bg-ink/40 px-3 py-2">
      <span className="text-slate-400">{label}</span>
      <span className="text-right font-medium text-slate-100">{value}</span>
    </div>
  );
}

function KnowledgeGraph({
  graph,
  relationshipFilter,
  onRelationshipFilter,
  onFocusEntity,
  semanticGraphResponse,
}: {
  graph: GraphData;
  relationshipFilter: string;
  onRelationshipFilter: (value: string) => void;
  onFocusEntity: (node: GraphNode) => void;
  semanticGraphResponse: SemanticGraphResponse;
}) {
  const width = 1500;
  
  const visibleNodes = graph.nodes;
  const visibleEdges = graph.edges;

  const maxLayerCount = Math.max(
    1,
    visibleNodes.filter((node) => node.kind === "source").length,
    visibleNodes.filter((node) => node.kind === "document").length,
    visibleNodes.filter((node) => node.kind === "related_entity").length,
  );
  
  const height = Math.max(640, maxLayerCount * 92 + 150);
  const positions = useMemo(() => layoutGraphNodes(visibleNodes, width, height), [visibleNodes, height]);
  const [activeNodeId, setActiveNodeId] = useState("selected");
  const [activeEdgeId, setActiveEdgeId] = useState("");

  useEffect(() => {
    if (!visibleNodes.some((node) => node.id === activeNodeId)) {
      setActiveNodeId("selected");
      setActiveEdgeId("");
    }
  }, [visibleNodes, activeNodeId]);

  const activeNode = visibleNodes.find((node) => node.id === activeNodeId) ?? visibleNodes.find((node) => node.id === "selected");
  const activeEdge = visibleEdges.find((edge) => edgeKey(edge) === activeEdgeId);
  const connectedEdges = activeNode ? visibleEdges.filter((edge) => edge.source === activeNode.id || edge.target === activeNode.id) : [];
  
  const contextEdgeKeys = new Set<string>();
  const connectedNodeIds = new Set<string>();
  if (activeEdge) {
    contextEdgeKeys.add(edgeKey(activeEdge));
    connectedNodeIds.add(activeEdge.source);
    connectedNodeIds.add(activeEdge.target);
  } else if (activeNode?.id === "selected") {
    visibleEdges.forEach((edge) => {
      contextEdgeKeys.add(edgeKey(edge));
      connectedNodeIds.add(edge.source);
      connectedNodeIds.add(edge.target);
    });
  } else {
    connectedEdges.forEach((edge) => {
      contextEdgeKeys.add(edgeKey(edge));
      connectedNodeIds.add(edge.source);
      connectedNodeIds.add(edge.target);
    });
  }
  if (activeNode) connectedNodeIds.add(activeNode.id);

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_380px] text-slate-100">
      <div className="overflow-hidden rounded-xl border border-line bg-panel shadow-glow">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="text-xs font-semibold text-slate-400">
            ACTIVE LENS: <span className="text-cyanx font-bold uppercase">{relationshipFilter}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge tone="green">Source</Badge>
            <Badge tone="blue">Evidence Doc</Badge>
            <Badge tone="red">Focus Entity</Badge>
            <Badge tone="amber">Related Intel</Badge>
          </div>
        </div>
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full bg-[#f8fafc]/50" style={{ height: Math.min(height, 840) }}>
          <defs>
            <marker id="kg-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
            </marker>
            <marker id="kg-arrow-active" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L9,3 z" fill="#0ea5e9" />
            </marker>
          </defs>
          <g opacity="0.15">
            <rect x="34" y="58" width="228" height={height - 96} rx="18" fill="#e2e8f0" stroke="#cbd5e1" />
            <rect x="330" y="58" width="326" height={height - 96} rx="18" fill="#e0f2fe" stroke="#bae6fd" />
            <rect x="734" y="58" width="214" height={height - 96} rx="18" fill="#fee2e2" stroke="#fca5a5" />
            <rect x="1100" y="58" width="338" height={height - 96} rx="18" fill="#fef3c7" stroke="#fde68a" />
          </g>
          <g fill="#475569" fontSize="11" fontWeight="800" letterSpacing="0.1em">
            <text x="148" y="34" textAnchor="middle">OSINT SOURCES</text>
            <text x="493" y="34" textAnchor="middle">EVIDENCE DOCUMENTS</text>
            <text x="842" y="34" textAnchor="middle">FOCUS ENTITY</text>
            <text x={width - 210} y="34" textAnchor="middle">RELATED INTEL</text>
          </g>
          {visibleEdges.map((edge) => {
            const sourceNode = visibleNodes.find((node) => node.id === edge.source);
            const targetNode = visibleNodes.find((node) => node.id === edge.target);
            const sourceCenter = positions[edge.source];
            const targetCenter = positions[edge.target];
            if (!sourceNode || !targetNode || !sourceCenter || !targetCenter) return null;
            const source = nodeEdgePoint(sourceNode, sourceCenter, Math.sign(targetCenter.x - sourceCenter.x) || 1);
            const target = nodeEdgePoint(targetNode, targetCenter, Math.sign(sourceCenter.x - targetCenter.x) || -1);
            const highlighted = contextEdgeKeys.has(edgeKey(edge));
            const muted = !highlighted && Boolean(activeNode && activeNode.id !== "selected");
            const path = relationshipPath(source, target);
            const label = edge.predicate ?? edge.label;
            const truncatedLabel = label.length > 22 ? truncate(label, 22) : label;
            const labelPosition = relationshipLabelPosition(source, target);
            const showLabel = edgeKey(edge) === activeEdgeId || (!activeEdgeId && activeNode?.id !== "selected" && highlighted && connectedEdges.length <= 10);
            return (
              <g
                key={edgeKey(edge)}
                className="cursor-pointer"
                onClick={() => {
                  setActiveEdgeId(edgeKey(edge));
                  setActiveNodeId("");
                }}
              >
                <path
                  d={path}
                  fill="none"
                  stroke={highlighted ? "#0ea5e9" : "#94a3b8"}
                  strokeWidth={highlighted ? 3.0 : 1.4}
                  strokeOpacity={muted ? 0.12 : highlighted ? 0.9 : 0.4}
                  markerEnd={highlighted ? "url(#kg-arrow-active)" : "url(#kg-arrow)"}
                  strokeDasharray={edge.category === "noise/reference" ? "4,4" : undefined}
                />
                {showLabel ? (
                  <g transform={`translate(${labelPosition.x}, ${labelPosition.y})`}>
                    <rect x={-(truncatedLabel.length * 3.5 + 11)} y="-12" width={truncatedLabel.length * 7 + 22} height="22" rx="7" fill="#ffffff" stroke={highlighted ? "#0ea5e9" : "#d8e0ea"} strokeWidth={highlighted ? 2 : 1} />
                    <text textAnchor="middle" dominantBaseline="middle" fill={highlighted ? "#0ea5e9" : "#334155"} fontSize="10" fontWeight="700">
                      {truncatedLabel}
                    </text>
                  </g>
                ) : null}
              </g>
            );
          })}
          {visibleNodes.map((node) => {
            const pos = positions[node.id];
            if (!pos) return null;
            const active = node.id === activeNode?.id;
            const muted = Boolean(activeNode && activeNode.id !== "selected" && !connectedNodeIds.has(node.id));
            return (
              <GraphSvgNode
                key={node.id}
                node={node}
                x={pos.x}
                y={pos.y}
                active={active}
                muted={muted}
                onClick={() => {
                  setActiveNodeId(node.id);
                  setActiveEdgeId("");
                }}
              />
            );
          })}
        </svg>
      </div>
      <GraphInspector
        node={activeNode}
        edge={activeEdge}
        edges={connectedEdges}
        nodes={visibleNodes}
        onFocusEntity={onFocusEntity}
        semanticGraphResponse={semanticGraphResponse}
      />
    </div>
  );
}

function GraphSvgNode({
  node,
  x,
  y,
  active,
  muted,
  onClick,
}: {
  node: GraphNode;
  x: number;
  y: number;
  active: boolean;
  muted: boolean;
  onClick: () => void;
}) {
  const color = graphNodeColor(node);
  const label = truncate(node.label, node.kind === "document" ? 38 : node.kind === "related_entity" ? 22 : 24);
  const typeLabel = node.kind === "selected_entity" ? node.type : node.kind === "related_entity" ? node.entity_type ?? node.type : node.kind ?? node.type;
  
  // Risk borders
  const riskColor = 
    node.risk_level === "critical" ? "#ef4444" : 
    node.risk_level === "high" ? "#f59e0b" : 
    node.risk_level === "medium" ? "#3b82f6" : 
    "#64748b";

  if (node.kind === "document") {
    return (
      <g className="cursor-pointer" opacity={muted ? 0.36 : 1} onClick={onClick}>
        <rect x={x - 132} y={y - 34} width="264" height="68" rx="12" fill="#ffffff" stroke={active ? "#0ea5e9" : color} strokeWidth={active ? 3 : 1.7} />
        {/* Risk indicator line */}
        <line x1={x - 132} y1={y - 30} x2={x - 132} y2={y + 30} stroke={riskColor} strokeWidth="5" strokeLinecap="round" />
        <text x={x - 120} y={y - 8} textAnchor="start" fill="#0f172a" fontSize="11" fontWeight="700">
          {truncate(label, 34)}
        </text>
        <text x={x - 120} y={y + 13} textAnchor="start" fill="#475569" fontSize="9" fontWeight="600">
          DOCUMENT · {node.source_name ? truncate(node.source_name, 22) : "evidence"}
        </text>
      </g>
    );
  }
  if (node.kind === "related_entity") {
    return (
      <g className="cursor-pointer" opacity={muted ? 0.32 : 1} onClick={onClick}>
        <rect x={x - 98} y={y - 28} width="196" height="56" rx="12" fill="#ffffff" stroke={active ? "#0ea5e9" : color} strokeWidth={active ? 3 : 1.6} />
        <circle cx={x - 70} cy={y} r="17" fill={`${color}18`} stroke={color} strokeWidth="1.5" />
        <text x={x - 70} y={y + 3} textAnchor="middle" fill={color} fontSize="8" fontWeight="800">
          {nodeIconText(node)}
        </text>
        <text x={x - 42} y={y - 4} fill="#0f172a" fontSize="11" fontWeight="800">
          {truncate(label, 18)}
        </text>
        <text x={x - 42} y={y + 15} fill="#475569" fontSize="9" fontWeight="700">
          {truncate(formatGraphType(typeLabel), 20)}
        </text>
        {/* Risk dot indicator */}
        <circle cx={x + 80} cy={y - 12} r="4.5" fill={riskColor} />
      </g>
    );
  }
  const radius = node.kind === "selected_entity" ? 46 : 34;
  return (
    <g className="cursor-pointer" opacity={muted ? 0.34 : 1} onClick={onClick}>
      <circle cx={x} cy={y} r={radius} fill={`${color}18`} stroke={active ? "#0ea5e9" : color} strokeWidth={active ? 4 : 2.2} />
      <circle cx={x} cy={y - 18} r="13" fill="#ffffff" stroke={color} strokeWidth="1.5" />
      <text x={x} y={y - 14} textAnchor="middle" fill={color} fontSize="9" fontWeight="800">
        {nodeIconText(node)}
      </text>
      <text x={x} y={y + 8} textAnchor="middle" fill="#0f172a" fontSize="11" fontWeight="800">
        {label}
      </text>
      <text x={x} y={y + 27} textAnchor="middle" fill="#475569" fontSize="9" fontWeight="700">
        {formatGraphType(typeLabel).toUpperCase()}
      </text>
    </g>
  );
}

function GraphInspector({
  node,
  edge,
  edges,
  nodes,
  onFocusEntity,
  semanticGraphResponse,
}: {
  node: GraphNode | undefined;
  edge: GraphEdge | undefined;
  edges: GraphEdge[];
  nodes: GraphNode[];
  onFocusEntity: (node: GraphNode) => void;
  semanticGraphResponse: SemanticGraphResponse;
}) {
  const source = edge ? nodes.find((item) => item.id === edge.source) : undefined;
  const target = edge ? nodes.find((item) => item.id === edge.target) : undefined;

  // Resolve document nodes for the edge evidence
  const docNodes = useMemo(() => {
    if (!edge?.evidence_document_ids || !semanticGraphResponse) return [];
    return semanticGraphResponse.nodes.filter(
      (n) => n.kind === "document" && edge.evidence_document_ids?.includes(Number(n.value))
    );
  }, [edge, semanticGraphResponse]);

  return (
    <div className="rounded-xl border border-line bg-panel p-4 shadow-glow text-slate-100 flex flex-col justify-between min-h-[500px]">
      <div>
        <div className="mb-4 flex items-center justify-between gap-3 border-b border-line pb-2">
          <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">
            {edge ? "Relationship" : "Node"} Inspector
          </h3>
          {node ? (
            <Badge tone={graphNodeTone(node)}>{formatGraphType(node.kind ?? node.type)}</Badge>
          ) : null}
        </div>

        {/* Edge Details */}
        {edge && source && target ? (
          <div className="space-y-4">
            <div className="rounded-lg border border-cyanx/25 bg-cyanx/5 p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <Badge tone={relationshipTone(edge.predicate)}>{edge.predicate ?? edge.label}</Badge>
                <Badge tone="slate">{edge.category}</Badge>
              </div>
              <div className="text-sm font-bold text-slate-200">
                {source.label} → {target.label}
              </div>
              <p className="mt-2 text-xs leading-relaxed text-slate-400">
                {edge.rationale}
              </p>
            </div>

            <div className="space-y-2 text-xs">
              <StatusLine label="Confidence" value={`${((edge.confidence ?? 1.0) * 100).toFixed(0)}%`} />
              <StatusLine label="Source Reliability" value={edge.source_reliability ?? "unknown"} />
              <StatusLine label="Evidence Count" value={String(edge.evidence_count ?? 1)} />
            </div>

            {docNodes.length > 0 && (
              <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Evidence Documents</h4>
                <div className="space-y-2">
                  {docNodes.map((doc) => (
                    <a
                      key={doc.id}
                      href={doc.url || "#"}
                      target="_blank"
                      rel="noreferrer"
                      className="block rounded bg-ink/40 p-2 text-xs hover:border-cyanx border border-transparent transition"
                    >
                      <div className="font-semibold text-slate-200 line-clamp-1">{doc.label}</div>
                      <div className="text-[10px] text-slate-400">{doc.source_name}</div>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* Node Details */}
        {node && !edge ? (
          <div className="space-y-4">
            <div>
              <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400 mb-1">
                {formatGraphType(node.entity_type || node.type)}
              </div>
              <div className="text-lg font-bold text-slate-100">{node.title ?? node.label}</div>
              
              {node.badges && node.badges.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {node.badges.map((b) => (
                    <Badge key={b} tone={node.risk_level === "critical" ? "red" : node.risk_level === "high" ? "amber" : "blue"}>
                      {b}
                    </Badge>
                  ))}
                </div>
              )}

              {node.description ? (
                <p className="mt-3 text-xs leading-relaxed text-slate-400 whitespace-pre-wrap">
                  {node.description}
                </p>
              ) : null}
            </div>

            <div className="space-y-2 text-xs">
              <StatusLine label="Risk Level" value={(node.risk_level ?? "info").toUpperCase()} />
              {node.confidence ? (
                <StatusLine label="Extract Confidence" value={`${(node.confidence * 100).toFixed(0)}%`} />
              ) : null}
              {node.evidence_count ? (
                <StatusLine label="Connected Evidence" value={`${node.evidence_count} docs`} />
              ) : null}
              {node.first_seen ? (
                <StatusLine label="First Seen" value={formatDate(node.first_seen)} />
              ) : null}
              {node.last_seen ? (
                <StatusLine label="Last Seen" value={formatDate(node.last_seen)} />
              ) : null}
              {node.source_name ? <StatusLine label="Publisher" value={node.source_name} /> : null}
            </div>
          </div>
        ) : null}
      </div>

      {/* Inspector Bottom Actions */}
      {node && !edge && (
        <div className="pt-4 border-t border-line mt-4 flex flex-wrap gap-2">
          {node.url ? (
            <a
              href={node.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded bg-cyanx px-3 py-1.5 text-xs font-bold text-ink hover:bg-sky-400 transition"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              Open Evidence
            </a>
          ) : null}
          {node.kind === "related_entity" && node.type !== "grouped" && (
            <button
              onClick={() => onFocusEntity(node)}
              className="rounded border border-line bg-ink px-3 py-1.5 text-xs font-bold text-slate-200 hover:bg-panel2 transition"
            >
              Focus Entity
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function layoutGraphNodes(nodes: GraphNode[], width: number, height: number) {
  const layers: Record<string, GraphNode[]> = {
    source: [],
    document: [],
    selected_entity: [],
    related_entity: [],
  };
  nodes.forEach((node) => {
    const key = node.kind ?? "related_entity";
    if (layers[key]) layers[key].push(node);
    else layers.related_entity.push(node);
  });
  const positions: Record<string, { x: number; y: number }> = {};
  distributeLayer(layers.source, 148, height, positions);
  distributeLayer(layers.document, 493, height, positions);
  distributeLayer(layers.selected_entity, 842, height, positions, height / 2);
  distributeLayer(layers.related_entity, width - 210, height, positions);
  return positions;
}

function distributeLayer(
  nodes: GraphNode[],
  x: number,
  height: number,
  positions: Record<string, { x: number; y: number }>,
  fixedY?: number
) {
  if (!nodes.length) return;
  nodes.forEach((node, index) => {
    const y = fixedY ?? ((index + 1) * height) / (nodes.length + 1);
    positions[node.id] = { x, y: Math.max(58, Math.min(height - 58, y)) };
  });
}

function nodeEdgePoint(node: GraphNode, position: { x: number; y: number }, direction: number) {
  return { x: position.x + direction * nodeHorizontalExtent(node), y: position.y };
}

function nodeHorizontalExtent(node: GraphNode) {
  if (node.kind === "document") return 132;
  if (node.kind === "related_entity") return 98;
  if (node.kind === "selected_entity") return 48;
  return 36;
}

function relationshipPath(source: { x: number; y: number }, target: { x: number; y: number }) {
  const mid = source.x + (target.x - source.x) * 0.5;
  return `M ${source.x} ${source.y} C ${mid} ${source.y}, ${mid} ${target.y}, ${target.x} ${target.y}`;
}

function relationshipLabelPosition(source: { x: number; y: number }, target: { x: number; y: number }) {
  return { x: source.x + (target.x - source.x) * 0.52, y: source.y + (target.y - source.y) * 0.48 - 10 };
}

function edgeKey(edge: GraphEdge) {
  return edge.id ?? `${edge.source}->${edge.target}:${edge.label}`;
}

function graphNodeColor(node: GraphNode) {
  if (node.kind === "source") return "#0f766e"; // teal
  if (node.kind === "document") {
    if (node.entity_type === "advisory") return "#dc2626"; // red
    return "#0369a1"; // blue
  }
  if (node.kind === "selected_entity") return "#dc2626"; // red
  if (node.type === "grouped") return "#64748b"; // grey for collapsed group
  if (node.entity_type === "cve") return "#e11d48"; // rose for CVEs
  if (node.entity_type === "malware_family") return "#7c3aed"; // violet for malware
  if (node.entity_type === "brand") return "#db2777"; // pink for brand
  if (node.entity_type === "package") return "#0284c7"; // light blue
  if (node.entity_type === "vendor" || node.entity_type === "product") return "#d97706"; // amber
  return "#b45309"; // brown/orange
}

function graphNodeTone(node: GraphNode): "slate" | "blue" | "green" | "amber" | "red" {
  if (node.kind === "source") return "green";
  if (node.kind === "document") return "blue";
  if (node.kind === "selected_entity") return "red";
  if (node.risk_level === "critical") return "red";
  if (node.risk_level === "high") return "amber";
  if (node.risk_level === "medium") return "blue";
  return "slate";
}

function nodeIconText(node: GraphNode) {
  if (node.kind === "source") return "SRC";
  if (node.kind === "selected_entity") return "FOC";
  if (node.type === "grouped") return "GRP";
  return (node.entity_type ?? node.type ?? "ENT").slice(0, 3).toUpperCase();
}

function formatGraphType(value?: string) {
  if (!value) return "entity";
  return value.replace(/_/g, " ");
}

function relationshipTone(relationship?: string): "slate" | "blue" | "green" | "amber" | "red" {
  const rel = (relationship ?? "").toUpperCase();
  if (["PUBLISHED", "PUBLISHES"].includes(rel)) return "green";
  if (["ASSERTS", "MENTIONS", "HAS_CVE"].includes(rel)) return "blue";
  if (["CO_OCCURS", "AFFECTS_PACKAGE", "AFFECTS_VENDOR", "AFFECTS_PRODUCT", "HAS_SEVERITY"].includes(rel)) return "amber";
  if (["OBSERVED_PHISHING_URL", "OBSERVED_MALWARE_URL", "OBSERVED_IOC", "HOSTED_ON_IP", "TARGETS_BRAND", "ASSOCIATED_WITH_MALWARE"].includes(rel)) return "red";
  return "slate";
}

function relationshipDescription(edge: GraphEdge) {
  if (edge.relationship === "PUBLISHED") return "A public source published an evidence document.";
  if (edge.relationship === "MENTIONS") return "An evidence document mentions an extracted security entity.";
  if (edge.relationship === "CO_OCCURS") return "Two entities appear together in one or more evidence documents.";
  return edge.label;
}

function PriorityRow({ finding, compact = false }: { finding: PriorityFinding; compact?: boolean }) {
  return (
    <div className="rounded-xl border border-line bg-ink/40 p-4 shadow-sm hover:border-cyanx/30">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <PriorityBadge priority={finding.priority} />
            <Badge>{finding.entity_type}</Badge>
            <Badge tone={finding.confirmation.includes("corroborated") ? "green" : finding.confirmation.includes("social only") ? "amber" : "blue"}>
              {finding.confirmation}
            </Badge>
            <Badge tone={verdictTone(finding.analyst_verdict)}>{finding.analyst_verdict}</Badge>
          </div>
          <div className="mt-2 truncate text-lg font-semibold text-slate-100">{finding.value}</div>
          <div className="mt-2 text-xs text-slate-500">Reliability: {finding.source_reliability}</div>
        </div>
        <div className="text-right">
          <div className="text-2xl font-semibold text-white">{finding.score}</div>
          <div className="text-xs text-slate-400">{finding.mentions} mentions · {finding.source_count} sources</div>
        </div>
      </div>
      {!compact ? <p className="mt-3 text-sm text-slate-400">{finding.rationale[0]}</p> : null}
    </div>
  );
}

function DecisionMetric({ label, value, tone }: { label: string; value: string; tone: "slate" | "blue" | "green" | "amber" | "red" }) {
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <Badge tone={tone}>{value}</Badge>
    </div>
  );
}

function Metric({ label, value, icon: Icon, tone = "blue" }: { label: string; value: number; icon: ElementType; tone?: "blue" | "red" | "amber" | "green" }) {
  const color =
    tone === "red"
      ? "text-danger bg-danger/10 border-danger/30"
      : tone === "amber"
        ? "text-amberx bg-amberx/10 border-amberx/30"
        : tone === "green"
          ? "text-tealt bg-tealt/10 border-tealt/30"
          : "text-cyanx bg-cyanx/10 border-cyanx/30";
  return (
    <div className="rounded-xl border border-line bg-panel p-4 shadow-glow">
      <div className="flex items-center justify-between">
        <div className={`grid h-10 w-10 place-items-center rounded-lg border ${color}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="text-right text-3xl font-semibold">{value}</div>
      </div>
      <div className="mt-4 text-sm text-slate-400">{label}</div>
    </div>
  );
}

function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line bg-panel/95 p-4 shadow-glow ${className}`}>
      <h2 className="mb-4 text-base font-semibold text-slate-100">{title}</h2>
      {children}
    </section>
  );
}

function MiniPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-line bg-ink/30 p-4">
      <h3 className="mb-3 text-sm font-semibold text-slate-200">{title}</h3>
      {children}
    </div>
  );
}

function Badge({ children, tone = "slate" }: { children: ReactNode; tone?: "slate" | "blue" | "green" | "amber" | "red" }) {
  const styles = {
    slate: "border-slate-300 bg-slate-100 text-slate-700",
    blue: "border-cyanx/25 bg-cyanx/10 text-cyanx",
    green: "border-tealt/25 bg-tealt/10 text-tealt",
    amber: "border-amberx/25 bg-amberx/10 text-amberx",
    red: "border-danger/25 bg-danger/10 text-danger",
  };
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${styles[tone]}`}>{children}</span>;
}

function PriorityBadge({ priority }: { priority: string }) {
  const styles: Record<string, string> = {
    critical: "border-danger/30 bg-danger/10 text-danger",
    high: "border-amberx/30 bg-amberx/10 text-amberx",
    medium: "border-cyanx/30 bg-cyanx/10 text-cyanx",
    low: "border-slate-300 bg-slate-100 text-slate-700",
  };
  return <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold uppercase ${styles[priority] ?? styles.low}`}>{priority}</span>;
}

function SectionList({ title, items }: { title?: string; items: string[] }) {
  return (
    <div>
      {title ? <h3 className="mb-2 text-sm font-semibold text-slate-200">{title}</h3> : null}
      <ul className="space-y-2 text-sm text-slate-400">
        {items.map((item) => <li key={item}>- {item}</li>)}
      </ul>
    </div>
  );
}

function verdictTone(verdict: string): "slate" | "blue" | "green" | "amber" | "red" {
  if (verdict === "Patch/Remediate" || verdict === "Escalate") return "red";
  if (verdict === "Investigate") return "amber";
  if (verdict === "Monitor") return "blue";
  return "slate";
}

function reliabilityTone(label: string): "slate" | "blue" | "green" | "amber" | "red" {
  if (label.startsWith("high")) return "green";
  if (label === "medium") return "blue";
  if (label === "community") return "amber";
  if (label === "low") return "amber";
  return "slate";
}

function sourceTypeTone(sourceType: string): "slate" | "blue" | "green" | "amber" | "red" {
  if (sourceType === "structured_feed" || sourceType === "cert" || sourceType === "vendor" || sourceType === "threat_feed" || sourceType === "research") return "green";
  if (sourceType === "news" || sourceType === "rss") return "blue";
  if (sourceType === "social") return "amber";
  return "slate";
}

function postureTone(posture: string): "slate" | "blue" | "green" | "amber" | "red" {
  if (posture === "excellent" || posture === "strong") return "green";
  if (posture === "developing") return "amber";
  if (posture === "thin" || posture === "empty") return "red";
  return "blue";
}

function percentage(value: number) {
  return `${Math.round(value * 100)}%`;
}

function ExportButton({ icon: Icon, label, onClick }: { icon: ElementType; label: string; onClick: () => void }) {
  return (
    <button onClick={onClick} className="flex items-center gap-3 rounded-xl border border-line bg-ink/40 p-4 text-left hover:border-cyanx/40 hover:bg-cyanx/5">
      <Icon className="h-5 w-5 text-cyanx" />
      <span className="font-medium">{label}</span>
    </button>
  );
}

function download(name: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function formatDate(value: string | null) {
  if (!value) return "unknown";
  return new Date(value).toLocaleDateString();
}

function truncate(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}...` : value;
}

function ChatPage({
  messages,
  input,
  setInput,
  loading,
  error,
  citations,
  caveats,
  relatedEntities,
  llmConfigured,
  onSendPrompt,
  onClearChat,
}: {
  messages: Array<{ role: "user" | "assistant"; content: string }>;
  input: string;
  setInput: (v: string) => void;
  loading: boolean;
  error: string;
  citations: Array<{ document_id: number; title: string; source_name: string; url: string }>;
  caveats: string[];
  relatedEntities: Array<{ type: string; value: string }>;
  llmConfigured: boolean;
  onSendPrompt: (text: string) => void;
  onClearChat: () => void;
}) {
  const SUGGESTED_PROMPTS = [
    "What are the top critical threats?",
    "Summarize phishing activity.",
    "What data sources are weakest?",
    "Explain recent malware indicators.",
    "Which CVEs have the highest priority?",
    "What multilingual intelligence do we have?"
  ];

  return (
    <div className="space-y-5">
      {!llmConfigured ? (
        <div className="rounded-lg border border-danger/30 bg-danger/10 p-4 text-sm text-danger flex flex-col gap-2">
          <div className="font-semibold text-base">LLM Analyst Chat Disabled</div>
          <div>The chat interface is retrieval-augmented but requires a configured LLM provider to formulate analyst answers.</div>
          <div className="text-xs font-mono bg-ink/30 p-2 rounded mt-1 border border-line/50">
            Configure in your .env:<br />
            LLM_PROVIDER=openai_compatible<br />
            LLM_API_KEY=your_key_here<br />
            LLM_BASE_URL=...
          </div>
        </div>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
        {/* Main Chat Panel */}
        <div className="flex flex-col rounded-xl border border-line bg-panel p-4 shadow-glow min-h-[600px] justify-between">
          <div className="flex items-center justify-between border-b border-line pb-3 mb-4">
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Brain className="h-5 w-5 text-cyanx" />
              CTI Analyst Chat Session
            </h2>
            {messages.length > 0 ? (
              <button
                onClick={onClearChat}
                className="text-xs px-2 py-1 rounded border border-line bg-ink/30 hover:bg-ink hover:text-white transition"
              >
                Clear History
              </button>
            ) : null}
          </div>

          {error ? (
            <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-3 text-sm text-amber-100 mb-4">
              <div className="font-semibold mb-1">Copilot Notification</div>
              <div>{error}</div>
            </div>
          ) : null}

          {/* Transcript Area */}
          <div className="flex-1 overflow-y-auto max-h-[500px] mb-4 space-y-4 pr-2 scrollbar-thin flex flex-col">
            {messages.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8 my-auto text-slate-400">
                <div className="grid h-16 w-16 place-items-center rounded-2xl border border-cyanx/20 bg-cyanx/5 mb-4">
                  <Brain className="h-8 w-8 text-cyanx" />
                </div>
                <h3 className="text-lg font-semibold text-slate-200 mb-2">Ready to Assist</h3>
                <p className="max-w-md text-sm leading-relaxed">
                  Ask me questions about CISA vulnerabilities, OSINT feeds, trending entities, or social media coverage. I will retrieve context from the local threat intelligence database first.
                </p>
                <div className="mt-6 flex flex-wrap gap-2 justify-center max-w-lg">
                  {SUGGESTED_PROMPTS.slice(0, 3).map((prompt) => (
                    <button
                      key={prompt}
                      onClick={() => onSendPrompt(prompt)}
                      className="rounded-full border border-line bg-ink/30 px-3 py-1.5 text-xs text-slate-300 hover:bg-cyanx/10 hover:border-cyanx/30 transition"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex flex-col max-w-[85%] rounded-xl p-3 border ${
                    msg.role === "user"
                      ? "bg-cyanx/10 border-cyanx/20 self-end text-slate-100"
                      : "bg-ink/30 border-line self-start text-slate-200"
                  }`}
                >
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    {msg.role === "user" ? "Analyst Question" : "Copilot Answer"}
                  </div>
                  <div className="text-sm whitespace-pre-wrap leading-relaxed">
                    {msg.content}
                  </div>
                </div>
              ))
            )}

            {loading ? (
              <div className="flex flex-col max-w-[85%] rounded-xl p-3 border bg-ink/30 border-line self-start text-slate-200">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                  Copilot Answer
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <span className="h-2 w-2 rounded-full bg-cyanx animate-pulse"></span>
                  Retrieving intelligence and compiling response...
                </div>
              </div>
            ) : null}
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (input.trim() && !loading && llmConfigured) {
                onSendPrompt(input);
              }
            }}
            className="flex items-center gap-2 border-t border-line pt-3 mt-auto"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={loading || !llmConfigured}
              placeholder={llmConfigured ? "Query intelligence database (e.g. 'Show recent CVE-2024-3400 sightings')" : "LLM provider is not configured"}
              className="flex-1 rounded-lg border border-line bg-ink/50 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyanx/50 transition disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={loading || !input.trim() || !llmConfigured}
              className="rounded-lg bg-cyanx px-4 py-2 text-sm font-semibold text-ink hover:bg-sky-700 transition disabled:opacity-40"
            >
              Send
            </button>
          </form>
        </div>

        {/* Right Sidebar Panel */}
        <div className="space-y-5">
          {/* Suggested Prompts */}
          <Panel title="Suggested Analyst Prompts">
            <div className="space-y-2">
              {SUGGESTED_PROMPTS.map((prompt) => (
                <button
                  key={prompt}
                  onClick={() => onSendPrompt(prompt)}
                  disabled={loading || !llmConfigured}
                  className="w-full text-left rounded-lg border border-line bg-ink/30 px-3 py-2.5 text-xs font-semibold text-slate-300 hover:bg-cyanx/10 hover:border-cyanx/30 hover:text-slate-100 transition disabled:opacity-50"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </Panel>

          {/* Citations Panel */}
          {citations.length > 0 ? (
            <Panel title="Evidence Citations">
              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1 scrollbar-thin">
                {citations.map((citation, index) => (
                  <a
                    key={index}
                    href={citation.url}
                    target="_blank"
                    rel="noreferrer"
                    className="block rounded-lg border border-line bg-ink/40 p-3 hover:border-cyanx/40 transition group"
                  >
                    <div className="flex items-center justify-between gap-1 text-[10px] font-bold text-cyanx uppercase mb-1">
                      <span>{truncate(citation.source_name, 25)}</span>
                      <span className="text-slate-500">ID: {citation.document_id}</span>
                    </div>
                    <div className="text-xs font-medium text-slate-200 group-hover:text-cyanx line-clamp-2">
                      {citation.title}
                    </div>
                  </a>
                ))}
              </div>
            </Panel>
          ) : null}

          {/* Caveats Panel */}
          {caveats.length > 0 ? (
            <Panel title="Analyst Caveats">
              <ul className="space-y-2 text-xs text-slate-400">
                {caveats.map((caveat, index) => (
                  <li key={index} className="flex gap-2 items-start">
                    <span className="text-amberx font-semibold">!</span>
                    <span>{caveat}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}

          {/* Related Entities */}
          {relatedEntities.length > 0 ? (
            <Panel title="Related Entities">
              <div className="flex flex-wrap gap-1.5">
                {relatedEntities.map((entity, index) => (
                  <Badge key={index} tone="blue">
                    <span className="opacity-60 mr-1">{entity.type}:</span>
                    {entity.value}
                  </Badge>
                ))}
              </div>
            </Panel>
          ) : null}
        </div>
      </div>
    </div>
  );
}
