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
    "Accept": "application/vnd.github+json",
}


def collect_github_advisories(source: dict, allow_fallback: bool = True) -> list[Document]:
    token = os.getenv("GITHUB_TOKEN")
    url = source.get("api_url", "https://api.github.com/advisories")
    
    headers = {**HEADERS}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    try:
        response = httpx.get(url, headers=headers, timeout=30, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, list):
            return _documents_from_advisories(source, payload)
        else:
            raise ValueError("Expected list of advisories from GitHub API")
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
    return _documents_from_advisories(source, payload)


def _documents_from_advisories(source: dict, advisories: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    limit = int(source.get("limit", 20))
    
    for entry in advisories[:limit]:
        ghsa_id = str(entry.get("ghsa_id", "")).strip()
        summary = str(entry.get("summary", "")).strip()
        if not ghsa_id:
            continue
            
        cve_id = entry.get("cve_id")
        severity = entry.get("severity") or "unknown"
        description = entry.get("description") or ""
        published_at = entry.get("published_at")
        html_url = entry.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
        
        # Package and ecosystem extraction
        package_info = []
        vulns = entry.get("vulnerabilities") or []
        for vuln in vulns[:5]:
            pkg = vuln.get("package") or {}
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            if name and ecosystem:
                package_info.append(f"{ecosystem}:{name}")
        package_str = ", ".join(package_info) if package_info else "unknown"
        
        references = entry.get("references") or []
        references_str = ", ".join(references) if isinstance(references, list) else str(references)
        
        body_lines = [
            f"GHSA ID: {ghsa_id}",
            f"CVE ID: {cve_id or 'N/A'}",
            f"Severity: {severity}",
            f"Package/Ecosystem: {package_str}",
            f"Summary: {summary}",
            f"Description: {description}",
            f"References: {references_str}"
        ]
        body = normalize_text("\n".join(body_lines))
        
        # Determine appropriate source type (vendor or threat_feed)
        source_type = source.get("source_type", "vendor")
        
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source_type,
                url=html_url,
                title=f"{ghsa_id} - {summary[:100]}",
                body=body,
                published_at=_parse_date(published_at),
                language="en",
                raw_metadata={
                    "ghsa_id": ghsa_id,
                    "cve_id": cve_id,
                    "severity": severity,
                    "ecosystem": package_str,
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
