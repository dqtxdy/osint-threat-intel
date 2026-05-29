from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dateutil import parser as date_parser

from cti_pipeline.cleaning import normalize_text
from cti_pipeline.models import Document


HEADERS = {
    "User-Agent": "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)",
    "Accept": "application/json,*/*",
}


def collect_otx(source: dict, allow_fallback: bool = True) -> list[Document]:
    api_key = os.getenv("OTX_API_KEY") or os.getenv("ALIENVAULT_OTX_API_KEY")
    if not api_key:
        return _documents_from_fallback(source) if allow_fallback else []

    try:
        response = httpx.get(
            source["api_url"],
            headers={**HEADERS, "X-OTX-API-KEY": api_key},
            params={"limit": int(source.get("limit", 10))},
            timeout=30,
            follow_redirects=True,
        )
        response.raise_for_status()
        payload = response.json()
        return _documents_from_pulses(source, payload.get("results", []))
    except (httpx.HTTPError, json.JSONDecodeError):
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)


def _documents_from_fallback(source: dict) -> list[Document]:
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return []
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _documents_from_pulses(source, payload.get("results", payload.get("pulses", [])))


def _documents_from_pulses(source: dict, pulses: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    for pulse in pulses[: int(source.get("limit", 10))]:
        pulse_id = str(pulse.get("id", "")).strip()
        name = str(pulse.get("name") or "Unnamed OTX pulse").strip()
        if not pulse_id:
            continue
        indicators = pulse.get("indicators", []) if isinstance(pulse.get("indicators"), list) else []
        body = normalize_text(
            "\n".join(
                [
                    str(pulse.get("description") or ""),
                    f"Tags: {', '.join(pulse.get('tags', [])[:12]) if isinstance(pulse.get('tags'), list) else ''}",
                    f"Adversary: {pulse.get('adversary') or 'unknown'}",
                    f"TLP: {pulse.get('tlp') or 'unknown'}",
                    "References: " + ", ".join(str(ref) for ref in pulse.get("references", [])[:10])
                    if isinstance(pulse.get("references"), list)
                    else "",
                    "Indicators: " + ", ".join(_indicator_value(item) for item in indicators[:50]),
                ]
            )
        )
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "threat_feed"),
                url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                title=name,
                body=body,
                published_at=_parse_date(pulse.get("modified") or pulse.get("created")),
                language="en",
                raw_metadata={
                    "pulse_id": pulse_id,
                    "indicator_count": len(indicators),
                    "tags": pulse.get("tags", []),
                    "tlp": pulse.get("tlp"),
                },
            )
        )
    return documents


def _indicator_value(item: Any) -> str:
    if not isinstance(item, dict):
        return str(item)
    indicator_type = item.get("type") or item.get("indicator_type") or "indicator"
    indicator = item.get("indicator") or item.get("value") or ""
    return f"{indicator_type}: {indicator}"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
