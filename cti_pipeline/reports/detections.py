from __future__ import annotations

from datetime import date
from typing import Any

import yaml

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.storage.sqlite_store import SQLiteStore


def build_sigma_hunts(store: SQLiteStore, days: int = 7, limit: int = 10) -> str:
    rules = []
    for finding in build_priority_findings(store, days=days, limit=limit):
        if finding.entity_type not in {"cve", "attack_technique", "domain", "ip", "url"}:
            continue
        references = [doc["url"] for doc in finding.evidence_documents if doc.get("url")]
        rules.append(_rule_for_finding(finding, references))
    return "\n---\n".join(yaml.safe_dump(rule, sort_keys=False) for rule in rules)


def _rule_for_finding(finding: Any, references: list[str]) -> dict[str, Any]:
    tags = []
    if finding.entity_type == "attack_technique":
        tags.append(f"attack.{finding.value.lower()}")
    if finding.entity_type == "cve":
        tags.append("attack.initial_access")

    return {
        "title": f"Threat Hunt For {finding.value}",
        "id": f"capstone-{finding.entity_type}-{finding.value}".lower().replace(" ", "-").replace(".", "-"),
        "status": "experimental",
        "description": (
            f"Safe hunting stub generated from OSINT evidence for {finding.entity_type} {finding.value}. "
            "Tune logsource and field names before operational use."
        ),
        "references": references,
        "author": "LLM-Based CTI Capstone Team",
        "date": date.today().isoformat(),
        "tags": tags,
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"CommandLine|contains": finding.value},
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

