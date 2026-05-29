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


def collect_phishtank(source: dict, allow_fallback: bool = True) -> list[Document]:
    url = _feed_url(source)
    headers = {
        "User-Agent": os.getenv("PHISHTANK_USER_AGENT", DEFAULT_USER_AGENT),
        "Accept": "application/json,*/*",
    }
    try:
        response = httpx.get(url, headers=headers, timeout=45, follow_redirects=True)
        response.raise_for_status()
        return _documents_from_entries(source, response.json())
    except (httpx.HTTPError, json.JSONDecodeError):
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)


def _feed_url(source: dict) -> str:
    app_key = os.getenv("PHISHTANK_APP_KEY")
    if app_key and source.get("keyed_url_template"):
        return str(source["keyed_url_template"]).format(app_key=app_key)
    return source["url"]


def _documents_from_fallback(source: dict) -> list[Document]:
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return []
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _documents_from_entries(source, payload)


def _documents_from_entries(source: dict, entries: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    limit = int(source.get("limit", 25))
    for entry in entries[:limit]:
        phish_id = str(entry.get("phish_id", "")).strip()
        phish_url = str(entry.get("url", "")).strip()
        if not phish_id or not phish_url:
            continue
        target = str(entry.get("target") or "Unknown target")
        verification_time = _parse_date(entry.get("verification_time"))
        details = _detail_lines(entry.get("details", []))
        body = normalize_text(
            "\n".join(
                [
                    f"Verified active phishing URL: {phish_url}",
                    f"Target brand: {target}",
                    f"Verification status: {entry.get('verified', 'yes')}; online: {entry.get('online', 'yes')}",
                    *details,
                ]
            )
        )
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "threat_feed"),
                url=entry.get("phish_detail_url") or f"https://phishtank.org/phish_detail.php?phish_id={phish_id}",
                title=f"PhishTank {phish_id} - {target}",
                body=body,
                published_at=verification_time or _parse_date(entry.get("submission_time")),
                language="en",
                raw_metadata={
                    "phish_id": phish_id,
                    "target": target,
                    "verified": entry.get("verified"),
                    "online": entry.get("online"),
                    "phish_url_redacted": False,
                },
            )
        )
    return documents


def _detail_lines(details: Any) -> list[str]:
    if not isinstance(details, list):
        return []
    lines = []
    for detail in details[:5]:
        if not isinstance(detail, dict):
            continue
        if detail.get("ip_address"):
            lines.append(f"Hosting IP: {detail['ip_address']}")
        if detail.get("cidr_block"):
            lines.append(f"CIDR block: {detail['cidr_block']}")
        if detail.get("announcing_network"):
            lines.append(f"Announcing network: {detail['announcing_network']}")
    return lines


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
