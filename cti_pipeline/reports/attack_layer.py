from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cti_pipeline.storage.sqlite_store import SQLiteStore


def load_attack_catalog() -> dict[str, Any]:
    catalog_paths = [
        Path(__file__).parents[2] / "data" / "attack_enterprise_techniques.json",
        Path("data/attack_enterprise_techniques.json"),
        Path(__file__).parents[2] / "data" / "sample_attack_techniques.json",
        Path("data/sample_attack_techniques.json"),
    ]
    for path in catalog_paths:
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return {}


def build_attack_navigator_layer(store: SQLiteStore, days: int = 7) -> dict[str, Any]:
    catalog = load_attack_catalog()
    raw_trends = store.entity_trends(days=days, limit=500, entity_types=["attack_technique"])

    techniques = []
    ignored_count = 0

    for trend in raw_trends:
        tech_id = trend["value"].upper()
        if catalog:
            if tech_id in catalog:
                techniques.append((trend, catalog[tech_id]))
            else:
                ignored_count += 1
        else:
            # Fallback if catalog not loaded
            import re
            if re.match(r"^T\d{4}(?:\.\d{3})?$", tech_id):
                if tech_id.startswith("T0"):
                    ignored_count += 1
                else:
                    techniques.append((trend, {"technique_id": trend["value"], "name": "Unknown Technique", "tactics": []}))
            else:
                ignored_count += 1

    layer_techniques = []
    for trend, cat_item in techniques:
        tech_id = cat_item.get("technique_id", trend["value"])
        name = cat_item.get("name", "Unknown Technique")
        tactics = cat_item.get("tactics", [])
        if not tactics and cat_item.get("tactic"):
            tactics = [cat_item["tactic"]]

        mentions = int(trend["mentions"])
        source_count = int(trend["source_count"])
        score = min(100, mentions * 20 + source_count * 10)
        confirmation = trend["confirmation"]
        first_seen = trend["first_seen"] or ""
        last_seen = trend["last_seen"] or ""

        layer_techniques.append({
            "techniqueID": tech_id,
            "name": name,
            "tactic": ", ".join(tactics) if tactics else "",
            "tactics": tactics,
            "score": score,
            "comment": f"{name} ({', '.join(tactics) if tactics else 'No Tactic'}) - {mentions} mention(s), {source_count} source(s), {confirmation}",
            "enabled": True,
            "mention_count": mentions,
            "source_count": source_count,
            "confirmation": confirmation,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "supporting_document_count": mentions,
            "metadata": [
                {"name": "name", "value": name},
                {"name": "tactic", "value": ", ".join(tactics) if tactics else ""},
                {"name": "confirmation", "value": confirmation},
                {"name": "first_seen", "value": first_seen},
                {"name": "last_seen", "value": last_seen},
                {"name": "mention_count", "value": str(mentions)},
                {"name": "source_count", "value": str(source_count)},
                {"name": "supporting_document_count", "value": str(mentions)},
            ],
        })

    return {
        "name": f"OSINT CTI Technique Coverage - Last {days} Days",
        "versions": {"attack": "enterprise", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated from extracted ATT&CK technique references in the CTI OSINT pipeline.",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "ignored_invalid_ids_count": ignored_count,
        "techniques": layer_techniques,
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
            {"name": "ignored_invalid_ids_count", "value": str(ignored_count)},
        ],
    }


