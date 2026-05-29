from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from dateutil import parser as date_parser

from cti_pipeline.cleaning import normalize_text
from cti_pipeline.models import Document

DEFAULT_USER_AGENT = "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)"
HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "application/json,*/*",
}


def collect_urlhaus(source: dict, allow_fallback: bool = True) -> list[Document]:
    api_key = os.getenv("ABUSECH_AUTH_KEY") or os.getenv("URLHAUS_AUTH_KEY")
    url = source.get("api_url", "https://urlhaus-api.abuse.ch/v1/urls/recent/")
    
    headers = {**HEADERS}
    if api_key:
        headers["Auth-Key"] = api_key
        
    try:
        response = httpx.get(url, headers=headers, timeout=30, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") == "ok":
            return _documents_from_urls(source, payload.get("urls", []))
        else:
            raise ValueError(f"URLhaus query status not ok: {payload.get('query_status')}")
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
    return _documents_from_urls(source, payload.get("urls", []))


def _documents_from_urls(source: dict, urls: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    limit = int(source.get("limit", 25))
    
    for entry in urls[:limit]:
        url_id = str(entry.get("id", "")).strip()
        url_val = str(entry.get("url", "")).strip()
        if not url_id or not url_val:
            continue
            
        try:
            parsed = urlparse(url_val)
            host = parsed.netloc or parsed.path
        except Exception:
            host = "unknown host"
            
        tags = entry.get("tags") or []
        tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
        url_status = entry.get("url_status") or "unknown"
        threat = entry.get("threat") or "malware_download"
        reporter = entry.get("reporter") or "unknown"
        firstseen = entry.get("firstseen") or entry.get("dateadded") or entry.get("date_added") or ""
        
        body_lines = [
            f"Malicious URL: {url_val}",
            f"Host/Domain: {host}",
            f"Threat: {threat}",
            f"Status: {url_status}",
            f"Tags: {tags_str}",
            f"Reporter: {reporter}",
            f"First Seen: {firstseen}"
        ]
        body = normalize_text("\n".join(body_lines))
        
        urlhaus_link = entry.get("urlhaus_link") or f"https://urlhaus.abuse.ch/url/{url_id}/"
        
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "threat_feed"),
                url=urlhaus_link,
                title=f"URLhaus {url_id} - {host}",
                body=body,
                published_at=_parse_date(firstseen),
                language="en",
                raw_metadata={
                    "urlhaus_id": url_id,
                    "url": url_val,
                    "url_status": url_status,
                    "threat": threat,
                    "tags": tags,
                    "first_seen": firstseen,
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
