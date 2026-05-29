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

DEFAULT_USER_AGENT = "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)"
HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "application/json",
}


def collect_threatfox(source: dict, allow_fallback: bool = True) -> list[Document]:
    api_key = os.getenv("ABUSECH_AUTH_KEY") or os.getenv("THREATFOX_AUTH_KEY")
    if not api_key:
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)
        
    url = source.get("api_url", "https://threatfox-api.abuse.ch/api/v1/")
    headers = {
        **HEADERS,
        "Auth-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "query": "get_iocs",
        "days": 3
    }
    
    try:
        response = httpx.post(url, headers=headers, json=payload, timeout=30, follow_redirects=True)
        response.raise_for_status()
        res_data = response.json()
        if res_data.get("query_status") == "ok":
            return _documents_from_iocs(source, res_data.get("data", []))
        else:
            raise ValueError(f"ThreatFox query status not ok: {res_data.get('query_status')}")
    except Exception:
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)


def _documents_from_fallback(source: dict) -> list[Document]:
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return []
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _documents_from_iocs(source, payload.get("data", []))


def _documents_from_iocs(source: dict, iocs: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    limit = int(source.get("limit", 25))
    
    for entry in iocs[:limit]:
        ioc_id = str(entry.get("id", "")).strip()
        ioc = str(entry.get("ioc", "")).strip()
        if not ioc:
            continue
            
        ioc_type = entry.get("ioc_type") or "unknown"
        threat_type = entry.get("threat_type") or "unknown"
        malware_family = entry.get("malware") or "unknown"
        confidence = entry.get("confidence") or 75
        tags = entry.get("tags") or []
        tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
        reference = entry.get("reference") or ""
        first_seen = entry.get("first_seen") or ""
        
        body_lines = [
            f"Indicator of Compromise (IOC): {ioc}",
            f"IOC Type: {ioc_type}",
            f"Threat Type: {threat_type}",
            f"Malware Family: {malware_family}",
            f"Confidence Level: {confidence}%",
            f"Tags: {tags_str}",
            f"Reference: {reference}",
            f"First Seen: {first_seen}"
        ]
        body = normalize_text("\n".join(body_lines))
        
        doc_url = reference if (reference and reference.startswith("http")) else f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
        
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "threat_feed"),
                url=doc_url,
                title=f"ThreatFox {threat_type} - {ioc}",
                body=body,
                published_at=_parse_date(first_seen),
                language="en",
                raw_metadata={
                    "ioc_id": ioc_id,
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "threat_type": threat_type,
                    "malware_family": malware_family,
                    "confidence": confidence,
                    "tags": tags,
                }
            )
        )
    return documents


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = date_parser.parse(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None
