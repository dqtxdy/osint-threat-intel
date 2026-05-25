from __future__ import annotations

import json
import sqlite3

from cti_pipeline.models import Entity


def metadata_entities(row: sqlite3.Row) -> list[Entity]:
    if row["source_id"] != "cisa_kev":
        return []
    metadata = json.loads(row["raw_metadata"])
    entities: list[Entity] = []

    for entity_type, field_name in [
        ("vendor", "vendorProject"),
        ("product", "product"),
        ("kev_catalog", "cveID"),
        ("ransomware_use", "knownRansomwareCampaignUse"),
    ]:
        value = str(metadata.get(field_name, "")).strip()
        if value:
            normalized = value.upper() if entity_type == "kev_catalog" else value
            entities.append(
                Entity(
                    entity_type=entity_type,
                    value=normalized,
                    normalized_value=normalized,
                    confidence=1.0,
                )
            )

    return entities
