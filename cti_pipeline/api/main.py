from __future__ import annotations

from typing import Any, Literal
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.llm.reporting import LLMDisabledError, build_llm_report
from cti_pipeline.reports.analyst_report import build_report
from cti_pipeline.reports.attack_layer import build_attack_navigator_layer
from cti_pipeline.reports.detections import build_sigma_hunts
from cti_pipeline.reports.intelligence_pack import build_intelligence_pack
from cti_pipeline.reports.stix_export import build_stix_bundle
from cti_pipeline.settings import load_settings
from cti_pipeline.storage.sqlite_store import SQLiteStore


app = FastAPI(title="CTI Analyst Command Center API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GRAPH_ENTITY_TYPE_PRIORITY = {
    "kev_catalog": 0,
    "vendor": 1,
    "product": 2,
    "ransomware_use": 3,
    "attack_technique": 4,
    "cve": 5,
    "ip": 6,
    "domain": 7,
    "sha256": 8,
    "sha1": 9,
    "md5": 10,
}
GRAPH_HIDDEN_ENTITY_TYPES = {"url"}
GRAPH_EMPTY_VALUES = {"", "unknown", "n/a", "none"}


def get_store() -> SQLiteStore:
    settings = load_settings()
    store = SQLiteStore(settings.db_path)
    store.init_db()
    return store


@app.get("/api/health")
def health() -> dict[str, Any]:
    settings = load_settings()
    return {
        "status": "ok",
        "db_path": str(settings.db_path),
        "llm_provider": settings.llm_provider,
        "llm_model": settings.llm_model,
        "llm_configured": bool(settings.llm_api_key),
    }


@app.get("/api/overview")
def overview(days: int = 3650) -> dict[str, Any]:
    store = get_store()
    documents = store.recent_documents(days=days, limit=500)
    trends = store.entity_trends(days=days, limit=200)
    priorities = [finding.to_dict() for finding in build_priority_findings(store, days=days, limit=8)]
    source_coverage = build_source_coverage(store, days=days).to_dict()
    source_names = sorted({source["source_name"] for source in source_coverage["source_mix"]})
    source_types = sorted({source["source_type"] for source in source_coverage["source_mix"]})
    confirmations = _count_by(trends, "confirmation")
    return {
        "window_days": days,
        "counts": {
            "documents": source_coverage["documents"],
            "entities": store.entity_count(),
            "sources": source_coverage["sources"],
            "source_types": source_coverage["source_types"],
            "languages": source_coverage["languages"],
            "critical_priorities": sum(1 for item in priorities if item["priority"] == "critical"),
            "high_priorities": sum(1 for item in priorities if item["priority"] == "high"),
        },
        "source_names": source_names,
        "source_types": source_types,
        "confirmation_matrix": confirmations,
        "source_coverage": source_coverage,
        "top_priorities": priorities,
        "top_trends": trends[:10],
    }


@app.get("/api/source-coverage")
def source_coverage(days: int = 3650) -> dict[str, Any]:
    return build_source_coverage(get_store(), days=days).to_dict()


@app.get("/api/documents")
def documents(days: int = 3650, source: str | None = None, query: str | None = None) -> list[dict[str, Any]]:
    store = get_store()
    rows = store.recent_documents(days=days, limit=500)
    results = []
    query_lower = query.lower() if query else None
    for row in rows:
        if source and row["source_name"] != source and row["source_type"] != source:
            continue
        if query_lower and query_lower not in f"{row['title']} {row['body']}".lower():
            continue
        results.append(_document_row(row))
    return results


@app.get("/api/entities")
def entities(limit: int = 200) -> list[dict[str, Any]]:
    store = get_store()
    return [
        {"type": row["entity_type"], "value": row["normalized_value"], "mentions": row["mentions"]}
        for row in store.all_entities(limit=limit)
    ]


@app.get("/api/entities/{entity_type}/{value}")
def entity_detail(entity_type: str, value: str, days: int = 3650) -> dict[str, Any]:
    store = get_store()
    normalized_value = unquote(value)
    docs = [_document_row(row) for row in store.entity_documents(entity_type, normalized_value, limit=50)]
    
    co_occurring = []
    for row in store.co_occurring_entities(entity_type, normalized_value, limit=25):
        item = {
            "type": row["entity_type"],
            "value": row["normalized_value"],
            "shared_documents": row["shared_documents"],
        }
        if row["entity_type"] == "cve":
            item["enrichments"] = store.entity_enrichments("cve", row["normalized_value"])
        co_occurring.append(item)

    return {
        "type": entity_type,
        "value": normalized_value,
        "documents": docs,
        "enrichments": store.entity_enrichments(entity_type, normalized_value),
        "co_occurring": co_occurring,
        "timeline": store.entity_timeline(entity_type, normalized_value, days=days),
    }


@app.get("/api/entities/{entity_type}/{value}/graph")
def entity_graph(entity_type: str, value: str) -> dict[str, Any]:
    store = get_store()
    normalized_value = unquote(value)
    selected_id = "selected"
    nodes = [
        {
            "id": selected_id,
            "label": normalized_value,
            "type": entity_type,
            "kind": "selected_entity",
            "entity_type": entity_type,
            "value": normalized_value,
            "description": f"Focused {entity_type} entity selected by the analyst.",
        }
    ]
    edges = []

    for doc in store.entity_documents(entity_type, normalized_value, limit=10):
        doc_id = f"doc-{doc['id']}"
        source_id = f"source-{doc['source_id']}"
        published = doc["published_at"] or doc["collected_at"]
        nodes.append(
            {
                "id": source_id,
                "label": doc["source_name"],
                "type": doc["source_type"],
                "kind": "source",
                "source_id": doc["source_id"],
                "source_name": doc["source_name"],
                "source_type": doc["source_type"],
                "language": doc["language"],
                "description": f"{doc['source_name']} is a {doc['source_type']} OSINT source.",
            }
        )
        nodes.append(
            {
                "id": doc_id,
                "label": doc["title"],
                "type": "document",
                "kind": "document",
                "document_id": doc["id"],
                "title": doc["title"],
                "url": doc["url"],
                "source_name": doc["source_name"],
                "source_type": doc["source_type"],
                "language": doc["language"],
                "published_at": published,
                "description": doc["body"][:280],
            }
        )
        edges.append(
            {
                "id": f"{source_id}->{doc_id}",
                "source": source_id,
                "target": doc_id,
                "label": "published",
                "relationship": "PUBLISHED",
                "description": f"{doc['source_name']} published this evidence document.",
            }
        )
        edges.append(
            {
                "id": f"{doc_id}->{selected_id}",
                "source": doc_id,
                "target": selected_id,
                "label": "mentions",
                "relationship": "MENTIONS",
                "description": f"The document mentions {normalized_value}.",
                "document_id": doc["id"],
            }
        )
        for related in _select_graph_entities(store.document_entities(doc["id"], limit=40), entity_type, normalized_value, limit=5):
            related_id = f"entity-{related['entity_type']}-{related['normalized_value']}"
            nodes.append(
                {
                    "id": related_id,
                    "label": _graph_node_label(related["entity_type"], related["normalized_value"]),
                    "type": related["entity_type"],
                    "kind": "related_entity",
                    "entity_type": related["entity_type"],
                    "value": related["normalized_value"],
                    "evidence": related["evidence"],
                    "confidence": related["confidence"],
                    "description": _graph_entity_description(entity_type, normalized_value, related["entity_type"], related["normalized_value"]),
                }
            )
            edges.append(
                {
                    "id": f"{doc_id}->{related_id}",
                    "source": doc_id,
                    "target": related_id,
                    "label": _document_relation_label(related["entity_type"]),
                    "relationship": "MENTIONS",
                    "description": f"This evidence document mentions {related['normalized_value']} as a {related['entity_type']} entity.",
                    "document_id": doc["id"],
                }
            )

    for row in _select_graph_entities(store.co_occurring_entities(entity_type, normalized_value, limit=40), entity_type, normalized_value, limit=10):
        node_id = f"entity-{row['entity_type']}-{row['normalized_value']}"
        nodes.append(
            {
                "id": node_id,
                "label": _graph_node_label(row["entity_type"], row["normalized_value"]),
                "type": row["entity_type"],
                "kind": "related_entity",
                "entity_type": row["entity_type"],
                "value": row["normalized_value"],
                "shared_documents": row["shared_documents"],
                "description": _graph_entity_description(entity_type, normalized_value, row["entity_type"], row["normalized_value"]),
            }
        )
        edges.append(
            {
                "id": f"{selected_id}->{node_id}",
                "source": selected_id,
                "target": node_id,
                "label": _semantic_relation_label(entity_type, row["entity_type"], row["shared_documents"]),
                "relationship": "CO_OCCURS",
                "description": _semantic_relation_description(entity_type, normalized_value, row["entity_type"], row["normalized_value"], row["shared_documents"]),
                "shared_documents": row["shared_documents"],
            }
        )
    return {"nodes": _dedupe_nodes(nodes), "edges": _dedupe_edges(edges)}


@app.get("/api/entities/{entity_type}/{value}/semantic-graph")
def entity_semantic_graph(entity_type: str, value: str) -> dict[str, Any]:
    store = get_store()
    normalized_value = unquote(value)
    from cti_pipeline.graph.semantic import build_semantic_graph
    return build_semantic_graph(store, entity_type, normalized_value)


@app.get("/api/priorities")
def priorities(days: int = 3650, limit: int = 25) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in build_priority_findings(get_store(), days=days, limit=limit)]


@app.get("/api/trends")
def trends(days: int = 3650, limit: int = 100) -> list[dict[str, Any]]:
    return get_store().entity_trends(days=days, limit=limit)


@app.get("/api/report", response_class=PlainTextResponse)
def report(
    days: int = 3650,
    category: str | None = None,
    entity_type: str | None = None,
    value: str | None = None,
) -> str:
    return build_report(
        get_store(),
        days=days,
        category=category,
        entity_type=entity_type,
        value=unquote(value) if value else None,
    )


@app.get("/api/export-pack")
def export_pack(days: int = 3650, limit: int = 25) -> dict[str, Any]:
    return build_intelligence_pack(get_store(), days=days, limit=limit)


@app.get("/api/attack-layer")
def attack_layer(days: int = 3650) -> dict[str, Any]:
    return build_attack_navigator_layer(get_store(), days=days)


@app.get("/api/detections", response_class=PlainTextResponse)
def detections(days: int = 3650, limit: int = 10) -> str:
    return build_sigma_hunts(get_store(), days=days, limit=limit)


@app.get("/api/export-stix")
def export_stix(days: int = 3650, limit: int = 50) -> dict[str, Any]:
    return build_stix_bundle(get_store(), days=days, limit=limit)


@app.post("/api/run-pipeline")
def api_run_pipeline(
    days: int = Query(3650),
    source: str = Query("all"),
    live_only: bool = Query(False),
    fresh: bool = Query(False),
    enrich_limit: int | None = Query(50),
) -> dict[str, Any]:
    from cti_pipeline.cli import run_pipeline

    settings = load_settings()
    return run_pipeline(
        get_store(),
        settings,
        source=source,
        days=days,
        output=settings.db_path.parent / "processed" / "latest_report.md",
        allow_fallback=not live_only,
        fresh=fresh,
        enrich_limit=enrich_limit,
    )


@app.post("/api/gemini-report", response_class=PlainTextResponse)
def gemini_report(days: int = 3650) -> str:
    settings = load_settings()
    try:
        return build_llm_report(get_store(), settings, days=days)
    except LLMDisabledError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=12)
    days: int = Field(default=3650, ge=1, le=3650)


@app.post("/api/chat")
def api_chat(request: ChatRequest) -> Any:
    settings = load_settings()
    store = get_store()
    try:
        from cti_pipeline.llm.chat import build_chat_response
        msgs = [{"role": m.role, "content": m.content} for m in request.messages]
        return build_chat_response(store, settings, msgs, days=request.days)
    except LLMDisabledError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unexpected failure: {str(exc)}") from exc


def _document_row(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "source_name": row["source_name"],
        "source_type": row["source_type"],
        "url": row["url"],
        "title": row["title"],
        "body": row["body"],
        "language": row["language"],
        "published_at": row["published_at"],
        "collected_at": row["collected_at"],
    }


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[str(item[key])] = counts.get(str(item[key]), 0) + 1
    return counts


def _select_graph_entities(rows: list[Any], selected_type: str, selected_value: str, limit: int) -> list[Any]:
    rows = list(rows)
    candidates = []
    cve_values = {row["normalized_value"].upper() for row in rows if row["entity_type"] == "cve"}
    selected_value_lower = selected_value.lower()
    for row in rows:
        entity_type = row["entity_type"]
        value = row["normalized_value"]
        if entity_type == selected_type and value.lower() == selected_value_lower:
            continue
        if selected_type != "cve" and entity_type == "kev_catalog" and value.upper() in cve_values:
            continue
        if entity_type in GRAPH_HIDDEN_ENTITY_TYPES:
            continue
        if value.strip().lower() in GRAPH_EMPTY_VALUES:
            continue
        candidates.append(row)
    candidates.sort(key=_graph_entity_rank)
    return candidates[:limit]


def _graph_entity_rank(row: Any) -> tuple[int, int, str]:
    shared_documents = int(_row_value(row, "shared_documents", 0) or 0)
    entity_type = row["entity_type"]
    value = row["normalized_value"]
    return (-shared_documents, GRAPH_ENTITY_TYPE_PRIORITY.get(entity_type, 50), value.lower())


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def _document_relation_label(entity_type: str) -> str:
    labels = {
        "kev_catalog": "mentions KEV record",
        "vendor": "mentions vendor",
        "product": "mentions product",
        "ransomware_use": "mentions ransomware use",
        "attack_technique": "mentions ATT&CK",
        "cve": "mentions CVE",
        "ip": "mentions IP",
        "domain": "mentions domain",
        "sha256": "mentions hash",
        "sha1": "mentions hash",
        "md5": "mentions hash",
    }
    return labels.get(entity_type, f"mentions {entity_type}")


def _semantic_relation_label(selected_type: str, related_type: str, shared_documents: int) -> str:
    if selected_type == "vendor" and related_type == "product":
        return "has product"
    if selected_type == "vendor" and related_type == "cve":
        return "has CVE"
    if selected_type == "vendor" and related_type == "ransomware_use":
        return "ransomware use"
    if selected_type == "cve" and related_type == "kev_catalog":
        return "listed in KEV"
    if selected_type == "cve" and related_type == "vendor":
        return "has vendor"
    if selected_type == "cve" and related_type == "product":
        return "affects product"
    if selected_type == "cve" and related_type == "ransomware_use":
        return "ransomware use"
    if related_type == "attack_technique":
        return "maps to ATT&CK"
    if related_type in {"ip", "domain", "sha256", "sha1", "md5"}:
        return f"observed with ({shared_documents})"
    return f"co-occurs ({shared_documents})"


def _semantic_relation_description(selected_type: str, selected_value: str, related_type: str, related_value: str, shared_documents: int) -> str:
    if selected_type == "vendor" and related_type == "product":
        return f"{selected_value} is associated with product {related_value} across {shared_documents} evidence document(s)."
    if selected_type == "vendor" and related_type == "cve":
        return f"{selected_value} is associated with vulnerability {related_value} in the evidence set."
    if selected_type == "vendor" and related_type == "ransomware_use":
        return f"{selected_value} appears in evidence where ransomware use is marked as {related_value.lower()}."
    if selected_type == "cve" and related_type == "kev_catalog":
        return f"{selected_value} appears in CISA KEV evidence, which raises prioritization confidence."
    if selected_type == "cve" and related_type == "product":
        return f"{selected_value} is associated with affected product {related_value} in the evidence set."
    if selected_type == "cve" and related_type == "vendor":
        return f"{selected_value} is associated with vendor/project {related_value} in the evidence set."
    if related_type == "attack_technique":
        return f"{selected_value} is contextually mapped near ATT&CK technique {related_value}."
    if related_type in {"ip", "domain", "sha256", "sha1", "md5"}:
        return f"{related_value} is an observable indicator found near {selected_value} in {shared_documents} evidence document(s)."
    return f"{selected_value} and {related_value} appear together in {shared_documents} evidence document(s)."


def _graph_entity_description(selected_type: str, selected_value: str, related_type: str, related_value: str) -> str:
    if selected_type == "vendor" and related_type == "product":
        return f"Product connected to vendor/project {selected_value} through collected evidence."
    if selected_type == "vendor" and related_type == "cve":
        return f"Vulnerability connected to vendor/project {selected_value} through collected evidence."
    if selected_type == "vendor" and related_type == "ransomware_use":
        return f"Ransomware-use field observed in evidence connected to {selected_value}."
    if selected_type == "cve" and related_type == "kev_catalog":
        return f"CISA KEV confirmation for {selected_value}."
    if selected_type == "cve" and related_type == "product":
        return f"Affected product connected to {selected_value} through collected evidence."
    if selected_type == "cve" and related_type == "vendor":
        return f"Vendor or project connected to {selected_value} through collected evidence."
    if related_type == "attack_technique":
        return "MITRE ATT&CK technique reference extracted from the evidence."
    if related_type in {"ip", "domain", "sha256", "sha1", "md5"}:
        return f"Observable indicator co-mentioned with {selected_value}."
    return f"{related_value} is co-mentioned with {selected_value} in collected evidence."


def _graph_node_label(entity_type: str, value: str) -> str:
    if entity_type == "ransomware_use":
        return f"Ransomware: {value}"
    if entity_type == "kev_catalog":
        return f"KEV: {value}"
    return value


def _dedupe_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for node in nodes:
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        result.append(node)
    return result


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for edge in edges:
        key = edge.get("id") or f"{edge['source']}->{edge['target']}:{edge['label']}"
        if key in seen:
            continue
        seen.add(key)
        result.append(edge)
    return result
