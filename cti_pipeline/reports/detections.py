from __future__ import annotations

from datetime import date
from typing import Any

import yaml

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.storage.sqlite_store import SQLiteStore


def build_sigma_hunts(
    store: SQLiteStore,
    days: int = 7,
    limit: int = 10,
    entity_types: set[str] | None = None,
    log_category: str | None = None,
    log_product: str | None = None,
    min_priority: str | None = None,
) -> str:
    rules = []
    priority_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_prio_val = priority_order.get((min_priority or "low").lower(), 0)

    # Fetch priority findings (up to 100 to allow filtering and slicing to limit)
    all_findings = build_priority_findings(store, days=days, limit=100)

    count = 0
    for finding in all_findings:
        if count >= limit:
            break

        # Filter by entity types
        target_types = entity_types or {"cve", "attack_technique", "domain", "ip", "url"}
        if finding.entity_type not in target_types:
            continue

        # Filter by minimum priority
        finding_prio_val = priority_order.get(finding.priority.lower(), 0)
        if finding_prio_val < min_prio_val:
            continue

        references = [doc["url"] for doc in finding.evidence_documents if doc.get("url")]
        rules.append(_rule_for_finding(finding, references, log_category, log_product))
        count += 1

    if not rules:
        return "# No threat hunts matched the selected filters."

    return "\n---\n".join(yaml.safe_dump(rule, sort_keys=False) for rule in rules)


def _rule_for_finding(
    finding: Any,
    references: list[str],
    log_category: str | None = None,
    log_product: str | None = None,
) -> dict[str, Any]:
    tags = []
    if finding.entity_type == "attack_technique":
        tags.append(f"attack.{finding.value.lower()}")
    if finding.entity_type == "cve":
        tags.append("attack.initial_access")

    # Context-aware defaults
    category = log_category
    product = log_product or "windows"

    if not category:
        if finding.entity_type in {"domain", "url"}:
            category = "dns_query"
        elif finding.entity_type == "ip":
            category = "network_connection"
        else:
            category = "process_creation"

    # Context-aware detection field
    if finding.entity_type in {"domain", "url"}:
        selection = {"query|contains": finding.value}
    elif finding.entity_type == "ip":
        selection = {"DestinationIp": finding.value}
    else:
        selection = {"CommandLine|contains": finding.value}

    return {
        "title": f"Threat Hunt For {finding.entity_type.upper()} {finding.value}",
        "id": f"capstone-{finding.entity_type}-{finding.value}".lower().replace(" ", "-").replace(".", "-").replace(":", "-"),
        "status": "experimental",
        "description": (
            f"Safe hunting stub generated from OSINT evidence for {finding.entity_type} {finding.value}. "
            "Tune logsource and field names before operational use."
        ),
        "references": references,
        "author": "LLM-Based CTI Capstone Team",
        "date": date.today().isoformat(),
        "tags": tags,
        "logsource": {"category": category, "product": product},
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "falsepositives": ["Administrative testing", "benign scanner output", "vendor tooling"],
        "level": _sigma_level(finding.priority),
    }


def _sigma_level(priority: str) -> str:
    return {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get(priority, "low")

