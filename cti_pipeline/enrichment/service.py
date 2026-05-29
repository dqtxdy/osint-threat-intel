from __future__ import annotations

from cti_pipeline.config import load_sources
from cti_pipeline.enrichment.attack import enrich_attack_technique
from cti_pipeline.enrichment.nvd import enrich_cve
from cti_pipeline.enrichment.first_epss import enrich_epss_batch
from cti_pipeline.settings import Settings
from cti_pipeline.storage.sqlite_store import SQLiteStore


def enrich_entities(store: SQLiteStore, settings: Settings, limit: int | None = None, allow_fallback: bool = True) -> dict[str, int]:
    sources = load_sources(settings.sources_path)
    counts = {"cve": 0, "attack_technique": 0, "first_epss": 0}

    cve_rows = _prioritized_entities(store, "cve", limit)
    cve_ids = [row["normalized_value"] for row in cve_rows]
    
    epss_payloads = {}
    if cve_ids and "first_epss" in sources:
        epss_payloads = enrich_epss_batch(cve_ids, sources["first_epss"], allow_fallback=allow_fallback)

    for row in cve_rows:
        payload = enrich_cve(row["normalized_value"], sources["nvd"], allow_fallback=allow_fallback)
        if payload:
            store.upsert_entity_enrichment(row["id"], "nvd", payload)
            counts["cve"] += 1
            
        cve_upper = row["normalized_value"].upper()
        if cve_upper in epss_payloads:
            store.upsert_entity_enrichment(row["id"], "first_epss", epss_payloads[cve_upper])
            counts["first_epss"] += 1

    for row in _prioritized_entities(store, "attack_technique", limit):
        payload = enrich_attack_technique(row["normalized_value"], sources["mitre_attack"], allow_fallback=allow_fallback)
        if payload:
            store.upsert_entity_enrichment(row["id"], "mitre_attack", payload)
            counts["attack_technique"] += 1

    return counts


def _prioritized_entities(store: SQLiteStore, entity_type: str, limit: int | None) -> list:
    rows = store.entities_by_type(entity_type)
    rows_by_value = {row["normalized_value"]: row for row in rows}
    ordered = []
    seen: set[str] = set()

    for trend in store.top_entities(days=3650, limit=5000):
        if trend["entity_type"] != entity_type:
            continue
        value = trend["normalized_value"]
        row = rows_by_value.get(value)
        if row is None or value in seen:
            continue
        ordered.append(row)
        seen.add(value)

    ordered.extend(row for row in rows if row["normalized_value"] not in seen)
    return ordered[:limit]
