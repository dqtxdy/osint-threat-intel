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
}


def collect_x(source: dict, allow_fallback: bool = True) -> list[Document]:
    bearer_token = os.getenv("X_BEARER_TOKEN") or os.getenv("TWITTER_BEARER_TOKEN")
    if not bearer_token:
        return _documents_from_fallback(source) if allow_fallback else []

    documents: list[Document] = []
    headers = {**HEADERS, "Authorization": f"Bearer {bearer_token}"}
    try:
        with httpx.Client(headers=headers, timeout=30, follow_redirects=True) as client:
            for query in source.get("queries", []):
                response = client.get(
                    source["api_url"],
                    params={
                        "query": query,
                        "max_results": max(10, int(source.get("max_results", 10))),
                        "tweet.fields": "created_at,lang,author_id,public_metrics,entities,source",
                    },
                )
                response.raise_for_status()
                documents.extend(_documents_from_tweets(source, response.json().get("data", []), query=query))
    except httpx.HTTPError:
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)

    return documents


def _documents_from_fallback(source: dict) -> list[Document]:
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return []
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _documents_from_tweets(source, payload.get("tweets", []), query="fallback sample")


def _documents_from_tweets(source: dict, tweets: list[dict[str, Any]], query: str) -> list[Document]:
    documents: list[Document] = []
    for tweet in tweets:
        text = normalize_text(tweet.get("text", ""))
        tweet_id = str(tweet.get("id", "")).strip()
        if not text or not tweet_id:
            continue
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "social"),
                url=f"https://x.com/i/web/status/{tweet_id}",
                title=text[:120],
                body=text,
                published_at=_parse_date(tweet.get("created_at")),
                language=tweet.get("lang"),
                raw_metadata={
                    "tweet_id": tweet_id,
                    "query": query,
                    "author_id_redacted": bool(tweet.get("author_id")),
                    "public_metrics": tweet.get("public_metrics", {}),
                    "platform": "x",
                },
            )
        )
    return documents


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
