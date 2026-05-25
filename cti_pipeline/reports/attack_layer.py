from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cti_pipeline.storage.sqlite_store import SQLiteStore


def build_attack_navigator_layer(store: SQLiteStore, days: int = 7) -> dict[str, Any]:
    techniques = [
        trend for trend in store.entity_trends(days=days, limit=200)
        if trend["type"] == "attack_technique"
    ]
    return {
        "name": f"OSINT CTI Technique Coverage - Last {days} Days",
        "versions": {"attack": "enterprise", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated from extracted ATT&CK technique references in the CTI OSINT pipeline.",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": technique["value"],
                "score": min(100, int(technique["mentions"]) * 20 + int(technique["source_count"]) * 10),
                "comment": (
                    f"{technique['mentions']} mention(s), {technique['source_count']} source(s), "
                    f"{technique['confirmation']}"
                ),
                "enabled": True,
                "metadata": [
                    {"name": "confirmation", "value": technique["confirmation"]},
                    {"name": "first_seen", "value": technique["first_seen"] or ""},
                    {"name": "last_seen", "value": technique["last_seen"] or ""},
                ],
            }
            for technique in techniques
        ],
        "gradient": {
            "colors": ["#253044", "#1f9d8a", "#f2b84b", "#ef4444"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Observed", "color": "#1f9d8a"},
            {"label": "High frequency", "color": "#f2b84b"},
            {"label": "Critical", "color": "#ef4444"},
        ],
        "metadata": [
            {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
            {"name": "source", "value": "LLM-Based Threat Intelligence Gathering capstone"},
        ],
    }

