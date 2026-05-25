from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

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
    return {
        "type": entity_type,
        "value": normalized_value,
        "documents": docs,
        "enrichments": store.entity_enrichments(entity_type, normalized_value),
        "co_occurring": [
            {"type": row["entity_type"], "value": row["normalized_value"], "shared_documents": row["shared_documents"]}
            for row in store.co_occurring_entities(entity_type, normalized_value, limit=25)
        ],
        "timeline": store.entity_timeline(entity_type, normalized_value, days=days),
    }


@app.get("/api/entities/{entity_type}/{value}/graph")
def entity_graph(entity_type: str, value: str) -> dict[str, Any]:
    store = get_store()
    normalized_value = unquote(value)
    nodes = [{"id": "selected", "label": normalized_value, "type": entity_type}]
    edges = []
    for doc in store.entity_documents(entity_type, normalized_value, limit=12):
        doc_id = f"doc-{doc['id']}"
        source_id = f"source-{doc['source_id']}"
        nodes.append({"id": source_id, "label": doc["source_name"], "type": "source"})
        nodes.append({"id": doc_id, "label": doc["title"], "type": "document"})
        edges.append({"source": source_id, "target": doc_id, "label": "PUBLISHED"})
        edges.append({"source": doc_id, "target": "selected", "label": "MENTIONS"})
    for row in store.co_occurring_entities(entity_type, normalized_value, limit=12):
        node_id = f"{row['entity_type']}:{row['normalized_value']}"
        nodes.append({"id": node_id, "label": row["normalized_value"], "type": row["entity_type"]})
        edges.append({"source": "selected", "target": node_id, "label": f"{row['shared_documents']} shared"})
    return {"nodes": _dedupe_nodes(nodes), "edges": edges}


@app.get("/api/priorities")
def priorities(days: int = 3650, limit: int = 25) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in build_priority_findings(get_store(), days=days, limit=limit)]


@app.get("/api/trends")
def trends(days: int = 3650, limit: int = 100) -> list[dict[str, Any]]:
    return get_store().entity_trends(days=days, limit=limit)


@app.get("/api/report", response_class=PlainTextResponse)
def report(days: int = 3650) -> str:
    return build_report(get_store(), days=days)


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


def _dedupe_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for node in nodes:
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        result.append(node)
    return result
