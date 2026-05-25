from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.storage.sqlite_store import SQLiteStore


def build_intelligence_pack(store: SQLiteStore, days: int = 7, limit: int = 25) -> dict[str, Any]:
    priorities = [finding.to_dict() for finding in build_priority_findings(store, days=days, limit=limit)]
    source_coverage = build_source_coverage(store, days=days).to_dict()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_days": days,
        "summary": {
            "priority_count": len(priorities),
            "critical_count": sum(1 for item in priorities if item["priority"] == "critical"),
            "high_count": sum(1 for item in priorities if item["priority"] == "high"),
            "source_coverage_score": source_coverage["score"],
            "source_coverage_posture": source_coverage["posture"],
        },
        "source_coverage": source_coverage,
        "priorities": priorities,
        "trends": store.entity_trends(days=days, limit=limit),
    }


def write_intelligence_pack(store: SQLiteStore, output: Path, days: int = 7, limit: int = 25) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    pack = build_intelligence_pack(store, days=days, limit=limit)
    output.write_text(json.dumps(pack, indent=2, ensure_ascii=False), encoding="utf-8")
