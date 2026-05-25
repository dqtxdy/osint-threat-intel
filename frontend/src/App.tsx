import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  Brain,
  Download,
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
import type { AttackLayer, DocumentItem, EntityDetail, EntitySummary, GraphData, Health, Overview, PriorityFinding, SourceCoverage, TrendSignal } from "./types";

type Page = "overview" | "coverage" | "priorities" | "feed" | "workbench" | "graph" | "attack" | "detections" | "reports" | "exports" | "pipeline";

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
  const [report, setReport] = useState("");
  const [detections, setDetections] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [attackLayer, setAttackLayer] = useState<AttackLayer | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");

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
    api.entityDetail(selectedEntity.type, selectedEntity.value, DAYS).then(setEntityDetail).catch((error) => setNotice(String(error)));
    api.entityGraph(selectedEntity.type, selectedEntity.value).then(setGraph).catch((error) => setNotice(String(error)));
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

  async function runPipeline() {
    setNotice("Pipeline running...");
    try {
      await api.runPipeline(DAYS);
      await refresh();
      setNotice("Pipeline complete.");
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
                Run Pipeline
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
              {page === "coverage" && overview && <CoveragePage coverage={overview.source_coverage} />}
              {page === "priorities" && <PrioritiesPage priorities={priorities} />}
              {page === "feed" && <ThreatFeed documents={documents} />}
              {page === "workbench" && (
                <WorkbenchPage entities={entities} selected={selectedEntity} onSelect={setSelectedEntity} detail={entityDetail} />
              )}
              {page === "graph" && <GraphPage entities={entities} selected={selectedEntity} onSelect={setSelectedEntity} graph={graph} />}
              {page === "attack" && <AttackCoveragePage attackLayer={attackLayer} />}
              {page === "detections" && <DetectionBuilderPage detections={detections} />}
              {page === "reports" && <ReportsPage report={report} />}
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
  graph,
}: {
  entities: EntitySummary[];
  selected: EntitySummary | null;
  onSelect: (entity: EntitySummary) => void;
  graph: GraphData | null;
}) {
  return (
    <div className="space-y-4">
      <Panel title="Knowledge Graph">
        <select
          value={selected ? `${selected.type}|${selected.value}` : ""}
          onChange={(event) => {
            const [type, value] = event.target.value.split("|");
            const entity = entities.find((item) => item.type === type && item.value === value);
            if (entity) onSelect(entity);
          }}
          className="mb-4 rounded-lg border border-line bg-ink px-3 py-2 text-sm"
        >
          {entities.map((entity) => (
            <option key={`${entity.type}-${entity.value}`} value={`${entity.type}|${entity.value}`}>
              {entity.type} · {entity.value}
            </option>
          ))}
        </select>
        {graph ? <NetworkGraph graph={graph} /> : null}
      </Panel>
    </div>
  );
}

function ReportsPage({ report }: { report: string }) {
  const [gemini, setGemini] = useState("");
  const [error, setError] = useState("");
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
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Deterministic Analyst Report">
        <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-300 scrollbar-thin">{report}</pre>
      </Panel>
      <Panel title="Gemini Analyst Report">
        <button onClick={generateGemini} className="mb-4 flex items-center gap-2 rounded-lg bg-cyanx px-3 py-2 text-sm font-semibold text-ink hover:bg-sky-300">
          <Sparkles className="h-4 w-4" />
          Generate
        </button>
        {error ? <div className="rounded-lg border border-amberx/30 bg-amberx/10 p-3 text-sm text-amber-100">{error}</div> : null}
        {gemini ? <pre className="max-h-[65vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-300 scrollbar-thin">{gemini}</pre> : null}
      </Panel>
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
          Run Full Pipeline
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

function NetworkGraph({ graph }: { graph: GraphData }) {
  const width = 1100;
  const height = 560;
  const centerX = width / 2;
  const centerY = height / 2;
  const [focusedNode, setFocusedNode] = useState(graph.nodes[0]?.id ?? "");
  useEffect(() => {
    if (graph.nodes.length && !graph.nodes.some((node) => node.id === focusedNode)) {
      setFocusedNode(graph.nodes[0].id);
    }
  }, [graph.nodes, focusedNode]);

  const focused = graph.nodes.find((node) => node.id === focusedNode) ?? graph.nodes[0];
  const linkedNodeIds = useMemo(() => {
    if (!focusedNode) return new Set<string>();
    const ids = new Set<string>([focusedNode]);
    graph.edges.forEach((edge) => {
      if (edge.source === focusedNode) ids.add(edge.target);
      if (edge.target === focusedNode) ids.add(edge.source);
    });
    return ids;
  }, [focusedNode, graph.edges]);
  const positions = graph.nodes.reduce<Record<string, { x: number; y: number }>>((acc, node, index) => {
    if (node.id === "selected") {
      acc[node.id] = { x: centerX, y: centerY };
    } else {
      const angle = (Math.PI * 2 * index) / Math.max(1, graph.nodes.length - 1);
      const radius = node.type === "document" ? 190 : 260;
      acc[node.id] = { x: centerX + Math.cos(angle) * radius, y: centerY + Math.sin(angle) * radius };
    }
    return acc;
  }, {});
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-ink/50">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-wide text-slate-500">{focused?.type ?? "node"}</div>
          <div className="truncate text-sm font-semibold text-slate-100">{focused?.label ?? "Select a node"}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="green">source</Badge>
          <Badge tone="blue">document</Badge>
          <Badge tone="amber">entity</Badge>
        </div>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[560px] w-full">
        {graph.edges.map((edge, index) => {
          const source = positions[edge.source];
          const target = positions[edge.target];
          if (!source || !target) return null;
          const highlighted = edge.source === focusedNode || edge.target === focusedNode;
          return (
            <line
              key={index}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke={highlighted ? "#0369a1" : "#cbd5e1"}
              strokeOpacity={focusedNode ? (highlighted ? 0.9 : 0.28) : 0.7}
              strokeWidth={highlighted ? 2 : 1.2}
            />
          );
        })}
        {graph.nodes.map((node) => {
          const pos = positions[node.id];
          const color = node.type === "source" ? "#0f766e" : node.type === "document" ? "#0369a1" : node.id === "selected" ? "#dc2626" : "#b45309";
          const muted = focusedNode ? !linkedNodeIds.has(node.id) : false;
          return (
            <g
              key={node.id}
              className="cursor-pointer"
              onMouseEnter={() => setFocusedNode(node.id)}
              onClick={() => setFocusedNode(node.id)}
            >
              <circle
                cx={pos.x}
                cy={pos.y}
                r={node.id === focusedNode ? 30 : node.id === "selected" ? 26 : 19}
                fill={color}
                opacity={muted ? 0.08 : 0.2}
                stroke={color}
                strokeOpacity={muted ? 0.3 : 1}
                strokeWidth={node.id === focusedNode ? 3 : 2}
              />
              <text x={pos.x} y={pos.y + 38} textAnchor="middle" fill={muted ? "#94a3b8" : "#334155"} fontSize="11">
                {truncate(node.label, 28)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
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
  if (sourceType === "structured_feed" || sourceType === "cert" || sourceType === "vendor") return "green";
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
