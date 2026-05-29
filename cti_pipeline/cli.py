from __future__ import annotations

import argparse
from pathlib import Path

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.config import load_sources
from cti_pipeline.collectors.cisa_kev import collect_cisa_kev
from cti_pipeline.collectors.otx import collect_otx
from cti_pipeline.collectors.phishtank import collect_phishtank
from cti_pipeline.collectors.reddit import collect_reddit
from cti_pipeline.collectors.rss import collect_all_rss
from cti_pipeline.collectors.x import collect_x
from cti_pipeline.collectors.urlhaus import collect_urlhaus
from cti_pipeline.collectors.threatfox import collect_threatfox
from cti_pipeline.collectors.github_advisories import collect_github_advisories
from cti_pipeline.extractors.entities import extract_entities
from cti_pipeline.extractors.structured import metadata_entities
from cti_pipeline.enrichment.service import enrich_entities
from cti_pipeline.llm.reporting import LLMDisabledError, build_llm_report
from cti_pipeline.reports.analyst_report import build_report
from cti_pipeline.reports.intelligence_pack import write_intelligence_pack
from cti_pipeline.settings import load_settings
from cti_pipeline.storage.neo4j_store import Neo4jStore
from cti_pipeline.storage.sqlite_store import SQLiteStore


def collect_documents(store: SQLiteStore, sources: dict, source: str, allow_fallback: bool = True) -> tuple[int, int, int]:
    documents = []
    if source in {"rss", "all"}:
        documents.extend(collect_all_rss(sources.get("rss", [])))
    if source in {"cisa_kev", "all"}:
        documents.extend(collect_cisa_kev(sources["cisa_kev"], allow_fallback=allow_fallback))
    if source in {"reddit", "all"}:
        documents.extend(collect_reddit(sources["reddit"], allow_fallback=allow_fallback))
    if source in {"x", "all"} and "x" in sources:
        documents.extend(collect_x(sources["x"], allow_fallback=allow_fallback))
    if source in {"phishtank", "all"} and "phishtank" in sources:
        documents.extend(collect_phishtank(sources["phishtank"], allow_fallback=allow_fallback))
    if source in {"otx", "all"} and "otx" in sources:
        documents.extend(collect_otx(sources["otx"], allow_fallback=allow_fallback))
    if source in {"urlhaus", "all"} and "urlhaus" in sources:
        documents.extend(collect_urlhaus(sources["urlhaus"], allow_fallback=allow_fallback))
    if source in {"threatfox", "all"} and "threatfox" in sources:
        documents.extend(collect_threatfox(sources["threatfox"], allow_fallback=allow_fallback))
    if source in {"github_advisories", "all"} and "github_advisories" in sources:
        documents.extend(collect_github_advisories(sources["github_advisories"], allow_fallback=allow_fallback))
    inserted, duplicates = store.insert_documents(documents)
    return len(documents), inserted, duplicates


def extract_pending_entities(store: SQLiteStore, limit: int | None = None) -> tuple[int, int]:
    rows = store.fetch_documents_pending_extraction(limit=limit)
    entity_count = 0
    for row in rows:
        text = f"{row['title']}\n{row['body']}"
        entities = extract_entities(text) + metadata_entities(row)
        entity_count += store.insert_document_entities(row["id"], entities, evidence=text)
        store.mark_document_extracted(row["id"])
    return len(rows), entity_count


def write_report(
    store: SQLiteStore,
    days: int,
    output: Path,
    category: str | None = None,
    entity_type: str | None = None,
    value: str | None = None,
) -> None:
    report = build_report(store, days=days, category=category, entity_type=entity_type, value=value)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")


def run_pipeline(
    store: SQLiteStore,
    settings,
    source: str,
    days: int,
    output: Path,
    include_llm: bool = False,
    allow_fallback: bool = True,
    fresh: bool = False,
    enrich_limit: int | None = None,
) -> dict[str, int | str]:
    store.init_db()
    backup_path = None
    if fresh:
        backup_path = store.backup()
        store.clear_all()
    sources = load_sources(settings.sources_path)
    collected, inserted, duplicates = collect_documents(store, sources, source, allow_fallback=allow_fallback)
    processed, entity_mentions = extract_pending_entities(store)
    enrichment_counts = enrich_entities(store, settings, limit=enrich_limit, allow_fallback=allow_fallback)
    write_report(store, days=days, output=output)
    pack_output = output.with_name("intelligence_pack.json")
    write_intelligence_pack(store, output=pack_output, days=days)

    llm_output = ""
    if include_llm:
        llm_output_path = output.with_name("latest_llm_report.md")
        try:
            report = build_llm_report(store, settings, days=days)
            llm_output_path.write_text(report, encoding="utf-8")
            llm_output = str(llm_output_path)
        except LLMDisabledError:
            llm_output = "disabled"

    return {
        "collected": collected,
        "inserted": inserted,
        "duplicates": duplicates,
        "processed": processed,
        "entity_mentions": entity_mentions,
        "cve_enrichments": enrichment_counts["cve"],
        "attack_enrichments": enrichment_counts["attack_technique"],
        "epss_enrichments": enrichment_counts.get("first_epss", 0),
        "report": str(output),
        "intelligence_pack": str(pack_output),
        "llm_report": llm_output,
        "backup": str(backup_path) if backup_path else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT CTI pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="Initialize the SQLite database")

    collect_parser = subparsers.add_parser("collect", help="Collect public-source documents")
    collect_parser.add_argument("--source", choices=["rss", "cisa_kev", "reddit", "x", "phishtank", "otx", "urlhaus", "threatfox", "github_advisories", "all"], default="all")
    collect_parser.add_argument("--live-only", action="store_true", help="Disable fallback sample data")

    extract_parser = subparsers.add_parser("extract", help="Extract entities from collected documents")
    extract_parser.add_argument("--limit", type=int, default=None)

    report_parser = subparsers.add_parser("report", help="Generate a Markdown analyst report")
    report_parser.add_argument("--days", type=int, default=7)
    report_parser.add_argument("--output", type=Path, default=Path("data/processed/latest_report.md"))
    report_parser.add_argument("--category", choices=["vulnerabilities", "malware", "attack", "vendors"], default=None)
    report_parser.add_argument("--entity-type", default=None)
    report_parser.add_argument("--value", default=None)

    llm_report_parser = subparsers.add_parser("llm-report", help="Generate an evidence-bound LLM report")
    llm_report_parser.add_argument("--days", type=int, default=7)
    llm_report_parser.add_argument("--output", type=Path, default=Path("data/processed/latest_llm_report.md"))

    enrich_parser = subparsers.add_parser("enrich", help="Enrich extracted entities with NVD and ATT&CK context")
    enrich_parser.add_argument("--limit", type=int, default=None)
    enrich_parser.add_argument("--live-only", action="store_true", help="Disable fallback enrichment data")

    trends_parser = subparsers.add_parser("trends", help="Print top entity trend signals")
    trends_parser.add_argument("--days", type=int, default=7)
    trends_parser.add_argument("--limit", type=int, default=20)

    priority_parser = subparsers.add_parser("prioritize", help="Print explainable priority findings")
    priority_parser.add_argument("--days", type=int, default=7)
    priority_parser.add_argument("--limit", type=int, default=10)

    export_parser = subparsers.add_parser("export-pack", help="Export a JSON intelligence pack")
    export_parser.add_argument("--days", type=int, default=3650)
    export_parser.add_argument("--limit", type=int, default=25)
    export_parser.add_argument("--output", type=Path, default=Path("data/processed/intelligence_pack.json"))

    pipeline_parser = subparsers.add_parser("run-pipeline", help="Run collect, extract, enrich, and report")
    pipeline_parser.add_argument("--source", choices=["rss", "cisa_kev", "reddit", "x", "phishtank", "otx", "urlhaus", "threatfox", "github_advisories", "all"], default="all")
    pipeline_parser.add_argument("--days", type=int, default=3650)
    pipeline_parser.add_argument("--output", type=Path, default=Path("data/processed/latest_report.md"))
    pipeline_parser.add_argument("--include-llm", action="store_true")
    pipeline_parser.add_argument("--live-only", action="store_true", help="Disable fallback sample data and fallback enrichment")
    pipeline_parser.add_argument("--fresh", action="store_true", help="Back up and clear the SQLite database before collection")
    pipeline_parser.add_argument("--enrich-limit", type=int, default=50, help="Maximum CVE and ATT&CK entities to enrich during pipeline runs")

    subparsers.add_parser("sync-neo4j", help="Sync SQLite documents/entities to Neo4j")

    args = parser.parse_args()
    settings = load_settings()
    store = SQLiteStore(settings.db_path)

    if args.command == "init-db":
        store.init_db()
        print(f"Initialized database at {settings.db_path}")
        return

    if args.command == "collect":
        store.init_db()
        sources = load_sources(settings.sources_path)
        collected, inserted, duplicates = collect_documents(store, sources, args.source, allow_fallback=not args.live_only)
        print(f"Collected {collected} document(s): {inserted} inserted, {duplicates} duplicate(s)")
        return

    if args.command == "extract":
        store.init_db()
        processed, entity_count = extract_pending_entities(store, limit=args.limit)
        print(f"Processed {processed} document(s), linked {entity_count} entity mention(s)")
        return

    if args.command == "report":
        store.init_db()
        write_report(store, days=args.days, output=args.output, category=args.category, entity_type=args.entity_type, value=args.value)
        print(f"Wrote report to {args.output}")
        return

    if args.command == "llm-report":
        store.init_db()
        try:
            report = build_llm_report(store, settings, days=args.days)
        except LLMDisabledError as exc:
            raise SystemExit(str(exc)) from exc
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote LLM report to {args.output}")
        return

    if args.command == "enrich":
        store.init_db()
        counts = enrich_entities(store, settings, limit=args.limit, allow_fallback=not args.live_only)
        print(
            "Enriched "
            f"{counts['cve']} CVE entity/entities, "
            f"{counts['attack_technique']} ATT&CK technique entity/entities"
            + (f", and {counts['first_epss']} EPSS entity/entities" if "first_epss" in counts else "")
        )
        return

    if args.command == "trends":
        store.init_db()
        trends = store.entity_trends(days=args.days, limit=args.limit)
        for trend in trends:
            print(
                f"{trend['type']}\t{trend['value']}\t"
                f"mentions={trend['mentions']}\t"
                f"sources={trend['source_count']}\t"
                f"{trend['confirmation']}"
            )
        return

    if args.command == "prioritize":
        store.init_db()
        findings = build_priority_findings(store, days=args.days, limit=args.limit)
        for finding in findings:
            print(
                f"{finding.priority.upper()}\t{finding.score}\t"
                f"{finding.entity_type}\t{finding.value}\t{finding.confirmation}"
            )
            print(f"  Rationale: {' '.join(finding.rationale)}")
            print(f"  Evidence docs: {', '.join(str(doc['id']) for doc in finding.evidence_documents)}")
        return

    if args.command == "export-pack":
        store.init_db()
        write_intelligence_pack(store, output=args.output, days=args.days, limit=args.limit)
        print(f"Wrote intelligence pack to {args.output}")
        return

    if args.command == "run-pipeline":
        result = run_pipeline(
            store=store,
            settings=settings,
            source=args.source,
            days=args.days,
            output=args.output,
            include_llm=args.include_llm,
            allow_fallback=not args.live_only,
            fresh=args.fresh,
            enrich_limit=args.enrich_limit,
        )
        print("Pipeline complete")
        if result["backup"]:
            print(f"Backup: {result['backup']}")
        print(f"Collected: {result['collected']} ({result['inserted']} inserted, {result['duplicates']} duplicate)")
        print(f"Extraction: {result['processed']} document(s), {result['entity_mentions']} entity mention(s)")
        print(
            f"Enrichment: {result['cve_enrichments']} CVE, "
            f"{result['attack_enrichments']} ATT&CK"
            + (f", {result['epss_enrichments']} EPSS" if "epss_enrichments" in result else "")
        )
        print(f"Report: {result['report']}")
        print(f"Intelligence pack: {result['intelligence_pack']}")
        if args.include_llm:
            print(f"LLM report: {result['llm_report']}")
        return

    if args.command == "sync-neo4j":
        store.init_db()
        graph = Neo4jStore(settings)
        try:
            graph.sync_from_sqlite(store)
        finally:
            graph.close()
        print("Synced SQLite data to Neo4j")


if __name__ == "__main__":
    main()
