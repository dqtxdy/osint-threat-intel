from __future__ import annotations

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.storage.sqlite_store import SQLiteStore


REPORT_CATEGORIES = {
    "vulnerabilities": ("Vulnerabilities & Exposure", ["cve", "kev_catalog", "vendor", "product"]),
    "malware": ("Malware, Ransomware & Indicators", ["malware", "ransomware_use", "domain", "ip", "url", "md5", "sha1", "sha256"]),
    "attack": ("MITRE ATT&CK Techniques", ["attack_technique"]),
    "vendors": ("Vendors & Products", ["vendor", "product"]),
}


def build_report(
    store: SQLiteStore,
    days: int = 7,
    category: str | None = None,
    entity_type: str | None = None,
    value: str | None = None,
) -> str:
    if category or entity_type or value:
        return build_scoped_report(store, days=days, category=category, entity_type=entity_type, value=value)

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


def build_scoped_report(
    store: SQLiteStore,
    days: int = 7,
    category: str | None = None,
    entity_type: str | None = None,
    value: str | None = None,
) -> str:
    title, entity_types, normalized_value, excluded_values = _report_scope(category=category, entity_type=entity_type, value=value)
    top_entities = store.top_entities(
        days=days,
        limit=25,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    trends = store.entity_trends(
        days=days,
        limit=25,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    priorities = build_priority_findings(
        store,
        days=days,
        limit=12,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    documents = store.recent_documents_for_entities(
        days=days,
        limit=14,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    enriched_entities = store.enriched_entity_summary(
        days=days,
        limit=25,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    source_names = sorted({row["source_name"] for row in documents})
    languages = sorted({row["language"] for row in documents if row["language"]})
    source_types = sorted({row["source_type"] for row in documents})

    lines = [
        f"# Scoped Threat Intelligence Report - {title}",
        "",
        "## Scope",
        "",
        f"- Time window: last {days} days",
        f"- Entity types: {', '.join(entity_types)}",
        f"- Entity value: {normalized_value or 'any'}",
        f"- Matching evidence documents: {len(documents)}",
        f"- Matching entities: {len(top_entities)}",
        "",
        "## Executive Summary",
        "",
        _scoped_summary(title, top_entities, documents),
        "",
        "## Scope Coverage",
        "",
        f"- Sources represented: {len(source_names)}",
        f"- Source categories represented: {len(source_types)}",
        f"- Languages represented: {len(languages)} ({', '.join(languages) if languages else 'unknown'})",
        "",
        "### Sources",
        "",
    ]

    for source_name in source_names or ["No sources matched this scope."]:
        lines.append(f"- {source_name}")

    lines.extend(["", "## Priority Findings In Scope", ""])
    if priorities:
        for finding in priorities:
            lines.append(
                "- "
                f"[{finding.priority.upper()}] "
                f"`{finding.entity_type}` `{finding.value}` "
                f"(score {finding.score}): {finding.analyst_verdict}. "
                f"Evidence: {finding.mentions} mention(s) across {finding.source_count} source(s); "
                f"reliability {finding.source_reliability}."
            )
            for action in finding.recommended_actions[:2]:
                lines.append(f"  - Action: {action}")
    else:
        lines.append("- No prioritized findings matched this scope.")

    lines.extend(["", "## Key Entities In Scope", ""])
    if top_entities:
        for row in top_entities:
            lines.append(f"- `{row['entity_type']}` `{row['normalized_value']}`: {row['mentions']} mention(s)")
    else:
        lines.append("- No extracted entities matched this scope.")

    lines.extend(["", "## Trend Signals In Scope", ""])
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
        lines.append("- No trend signals matched this scope.")

    lines.extend(["", "## Enrichment Highlights", ""])
    highlights = _priority_enrichment_highlights(priorities) + _enrichment_highlights(enriched_entities)
    if highlights:
        lines.extend(_dedupe(highlights))
    else:
        lines.append("- No enrichment data is available for this scope.")

    lines.extend(["", "## Evidence Documents", ""])
    if documents:
        for row in documents:
            published = row["published_at"] or row["collected_at"]
            lines.append(f"- {published} | {row['source_name']} | [{row['title']}]({row['url']})")
    else:
        lines.append("- No source documents matched this scope.")

    lines.extend(["", "## Analyst Notes For This Scope", ""])
    lines.extend(_scope_notes(entity_types))
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


def _report_scope(category: str | None, entity_type: str | None, value: str | None) -> tuple[str, list[str], str | None, list[str]]:
    if entity_type:
        title = f"{entity_type} {value}" if value else f"{entity_type} Entities"
        return title, [entity_type], value, []
    if category:
        label, entity_types = REPORT_CATEGORIES.get(category, (category.replace("_", " ").title(), [category]))
        excluded_values = ["unknown", "n/a", "none"] if category == "malware" else []
        return label, entity_types, None, excluded_values
    return "All Intelligence", [], None, []


def _scoped_summary(title: str, top_entities, documents) -> str:
    if not documents:
        return f"No source documents matched the `{title}` scope in this time window."
    parts = [f"The `{title}` scope matched {len(documents)} evidence document(s)."]
    if top_entities:
        preview = ", ".join(f"{row['entity_type']} {row['normalized_value']}" for row in top_entities[:5])
        parts.append(f"Most visible scoped entities include {preview}.")
    return " ".join(parts)


def _scope_notes(entity_types: list[str]) -> list[str]:
    if any(entity_type in {"domain", "ip", "url", "md5", "sha1", "sha256", "malware", "ransomware_use"} for entity_type in entity_types):
        return [
            "- Validate indicators and malware labels against trusted sources before blocking.",
            "- Search DNS, proxy, endpoint, and EDR telemetry for sightings before escalation.",
            "- Treat social-only malware chatter as unconfirmed until supported by vendor, CERT, or structured feeds.",
        ]
    if "cve" in entity_types or "kev_catalog" in entity_types:
        return [
            "- Prioritize CVEs that appear in CISA KEV, vendor advisories, or multiple independent sources.",
            "- Confirm product exposure, patch status, compensating controls, and exploitability.",
            "- Preserve source links as evidence for remediation decisions.",
        ]
    if "attack_technique" in entity_types:
        return [
            "- Map ATT&CK techniques to available telemetry and detection coverage.",
            "- Use this report as a hunting starting point, not as proof of compromise.",
            "- Connect technique sightings back to source documents and affected assets.",
        ]
    return [
        "- Review evidence documents before escalating scoped findings.",
        "- Prefer corroborated findings over social-only mentions.",
        "- Keep analyst judgement in the loop for prioritization and response.",
    ]


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
            if entity["type"] == "cve" and enrichment["provider"] == "first_epss":
                epss = payload.get("epss")
                percentile = payload.get("percentile")
                percentile_text = f" (percentile {percentile})" if percentile is not None else ""
                highlights.append(f"- `{entity['value']}`: EPSS {epss}{percentile_text}")
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
            if finding.entity_type == "cve" and enrichment["provider"] == "first_epss":
                epss = payload.get("epss")
                percentile = payload.get("percentile")
                percentile_text = f" (percentile {percentile})" if percentile is not None else ""
                highlights.append(f"- `{finding.value}`: EPSS {epss}{percentile_text}")
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
