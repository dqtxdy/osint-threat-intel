from __future__ import annotations

from datetime import datetime, timezone

import feedparser
import httpx
from dateutil import parser as date_parser

from cti_pipeline.cleaning import clean_html
from cti_pipeline.models import Document


HEADERS = {
    "User-Agent": "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)",
    "Accept": "application/rss+xml,application/xml,text/xml,text/html,*/*",
}


def collect_rss_feed(source: dict) -> list[Document]:
    response = httpx.get(source["url"], timeout=30, headers=HEADERS, follow_redirects=True)
    response.raise_for_status()
    feed = feedparser.parse(response.text)
    documents: list[Document] = []

    for entry in feed.entries:
        published_at = _parse_date(entry.get("published") or entry.get("updated"))
        body = entry.get("summary") or entry.get("description") or ""
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "rss"),
                url=entry.get("link", ""),
                title=clean_html(entry.get("title", "")),
                body=clean_html(body),
                published_at=published_at,
                language=source.get("language_hint"),
                raw_metadata={
                    "feed_title": feed.feed.get("title"),
                    "entry_id": entry.get("id"),
                },
            )
        )

    return documents


def collect_all_rss(sources: list[dict]) -> list[Document]:
    documents: list[Document] = []
    for source in sources:
        try:
            documents.extend(collect_rss_feed(source))
        except httpx.HTTPError:
            continue
    return documents


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
