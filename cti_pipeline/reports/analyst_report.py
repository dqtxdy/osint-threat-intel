from __future__ import annotations

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.storage.sqlite_store import SQLiteStore


def build_report(store: SQLiteStore, days: int = 7) -> str:
    top_entities = store.top_entities(days=days, limit=20)
    trends = store.entity_trends(days=days, limit=10)
    priorities = build_priority_findings(store, days=days, limit=8)
    coverage = build_source_coverage(store, days=days)
    documents = store.recent_documents(days=days, limit=10)
    enriched_entities = store.enriched_entity_summary(days=days, limit=20)
    source_names = sorted({source.source_name for source in coverage.source_mix})

    lines = [
        f"# Threat Intelligence Report - Last {days} Days",
        "",
        "## Executive Summary",
        "",
        _summary(top_entities, documents, coverage.documents),
        "",
        "## Collection Coverage",
        "",
        f"- Coverage score: {coverage.score}/100 ({coverage.posture})",
        f"- Sources: {coverage.sources}; source categories: {coverage.source_types}; languages: {coverage.languages}",
        f"- Social/community documents: {coverage.social_documents}; trusted source documents: {coverage.trusted_documents}",
        "",
        "### Source Mix",
        "",
    ]

    if coverage.source_mix:
        for source in coverage.source_mix:
            lines.append(
                "- "
                f"{source.source_name} ({source.source_type}, {source.language}): "
                f"{source.documents} document(s), reliability {source.reliability}"
            )
    else:
        lines.append("- No source coverage is available yet.")

    lines.extend(["", "### Coverage Gaps", ""])
    for gap in coverage.gaps or ["No major coverage gaps detected."]:
        lines.append(f"- {gap}")

    lines.extend(["", "### Collection Recommendations", ""])
    for recommendation in coverage.recommendations:
        lines.append(f"- {recommendation}")

    lines.extend(
        [
            "",
            "## Priority Findings",
            "",
        ]
    )

    if priorities:
        for finding in priorities:
            lines.append(
                "- "
                f"[{finding.priority.upper()}] "
                f"`{finding.entity_type}` `{finding.value}` "
                f"(score {finding.score}): {finding.analyst_verdict}. "
                f"Reliability: {finding.source_reliability}; "
                f"evidence: {finding.mentions} mention(s) across {finding.source_count} source(s)."
            )
    else:
        lines.append("- No prioritized findings are available yet.")

    lines.extend(
        [
            "",
            "## Key Entities",
            "",
        ]
    )

    if top_entities:
        for row in top_entities:
            lines.append(f"- `{row['entity_type']}` `{row['normalized_value']}`: {row['mentions']} mention(s)")
    else:
        lines.append("- No entities extracted yet.")

    lines.extend(["", "## Trend Signals", ""])
    if trends:
        for trend in trends:
            lines.append(
                "- "
                f"`{trend['type']}` `{trend['value']}`: "
                f"{trend['mentions']} mention(s), "
                f"{trend['source_count']} source(s), "
                f"{trend['confirmation']}"
            )
    else:
        lines.append("- No trend data available for this time window.")

    lines.extend(["", "## Enrichment Highlights", ""])
    highlights = _priority_enrichment_highlights(priorities) + _enrichment_highlights(enriched_entities)
    if highlights:
        lines.extend(_dedupe(highlights))
    else:
        lines.append("- No enrichment data yet. Run `python -m cti_pipeline.cli enrich`.")

    lines.extend(["", "## Recent Source Documents", ""])
    if documents:
        for row in documents:
            published = row["published_at"] or row["collected_at"]
            lines.append(f"- {published} | {row['source_name']} | [{row['title']}]({row['url']})")
    else:
        lines.append("- No recent documents collected yet.")

    lines.extend(["", "## Sources Represented", ""])
    if source_names:
        for source_name in source_names:
            lines.append(f"- {source_name}")
    else:
        lines.append("- No sources represented in this time window.")

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "",
            "- Treat social/community content as unverified until confirmed by vendor, CERT, or structured CTI feeds.",
            "- Prioritize CVEs that appear in CISA KEV or across multiple independent sources.",
            "- Review extracted indicators against warninglists before using them for blocking.",
        ]
    )

    return "\n".join(lines)


def _summary(top_entities, documents, document_total: int) -> str:
    if document_total == 0:
        return "No source documents are available for this time window."
    cves = [row["normalized_value"] for row in top_entities if row["entity_type"] == "cve"]
    techniques = [row["normalized_value"] for row in top_entities if row["entity_type"] == "attack_technique"]
    parts = [f"The pipeline collected {document_total} source document(s) in this time window."]
    if cves:
        parts.append(f"Most visible CVEs include {', '.join(cves[:5])}.")
    if techniques:
        parts.append(f"Observed ATT&CK technique references include {', '.join(techniques[:5])}.")
    return " ".join(parts)


def _enrichment_highlights(enriched_entities) -> list[str]:
    highlights: list[str] = []
    for entity in enriched_entities:
        for enrichment in entity["enrichments"]:
            payload = enrichment["payload"]
            if entity["type"] == "cve" and enrichment["provider"] == "nvd":
                severity = payload.get("severity") or "UNKNOWN"
                score = payload.get("cvss_score")
                score_text = f" CVSS {score}" if score is not None else ""
                highlights.append(f"- `{entity['value']}`: {severity}{score_text}")
            if entity["type"] == "attack_technique" and enrichment["provider"] == "mitre_attack":
                name = payload.get("name", "Unknown technique")
                tactic = payload.get("tactic", "Unknown tactic")
                highlights.append(f"- `{entity['value']}`: {name} ({tactic})")
    return highlights


def _priority_enrichment_highlights(priorities) -> list[str]:
    highlights: list[str] = []
    for finding in priorities:
        for enrichment in finding.enrichments:
            payload = enrichment["payload"]
            if finding.entity_type == "cve" and enrichment["provider"] == "nvd":
                severity = payload.get("severity") or "UNKNOWN"
                score = payload.get("cvss_score")
                score_text = f" CVSS {score}" if score is not None else ""
                highlights.append(f"- `{finding.value}`: {severity}{score_text}")
    return highlights


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
