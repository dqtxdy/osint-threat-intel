from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Document:
    source_id: str
    source_name: str
    source_type: str
    url: str
    title: str
    body: str
    published_at: datetime | None = None
    language: str | None = None
    collected_at: datetime = field(default_factory=utc_now)
    raw_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Entity:
    entity_type: str
    value: str
    normalized_value: str
    confidence: float = 1.0


@dataclass(frozen=True)
class ExtractionResult:
    document_id: int
    entities: list[Entity]

