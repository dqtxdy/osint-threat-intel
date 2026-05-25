from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def enrich_attack_technique(technique_id: str, source: dict, allow_fallback: bool = True) -> dict[str, Any] | None:
    if not allow_fallback:
        return None
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return None
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        techniques = json.load(handle)
    return techniques.get(technique_id.upper())
