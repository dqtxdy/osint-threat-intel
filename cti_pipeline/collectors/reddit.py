from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from cti_pipeline.cleaning import clean_html, normalize_text
from cti_pipeline.models import Document


def collect_reddit(source: dict, allow_fallback: bool = True) -> list[Document]:
    client_id = os.getenv("REDDIT_CLIENT_ID")
    client_secret = os.getenv("REDDIT_CLIENT_SECRET")
    user_agent = os.getenv("REDDIT_USER_AGENT", "pentest-capstone-cti-pipeline/0.1")

    try:
        if client_id and client_secret:
            return _collect_oauth(source, client_id, client_secret, user_agent)
        return _collect_public_json(source, user_agent)
    except httpx.HTTPError:
        if not allow_fallback:
            return []
        return _documents_from_fallback(source)


def _get_token(token_url: str, client_id: str, client_secret: str, user_agent: str) -> str:
    response = httpx.post(
        token_url,
        auth=(client_id, client_secret),
        data={"grant_type": "client_credentials"},
        headers={"User-Agent": user_agent},
        timeout=30,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def _collect_oauth(source: dict, client_id: str, client_secret: str, user_agent: str) -> list[Document]:
    token = _get_token(source["token_url"], client_id, client_secret, user_agent)
    posts: list[dict[str, Any]] = []
    with httpx.Client(
        base_url=source["api_base_url"],
        headers={"Authorization": f"Bearer {token}", "User-Agent": user_agent},
        timeout=30,
        follow_redirects=True,
    ) as client:
        for subreddit in source.get("subreddits", []):
            response = client.get(f"/r/{subreddit}/new", params={"limit": source.get("limit_per_subreddit", 25)})
            response.raise_for_status()
            children = response.json().get("data", {}).get("children", [])
            posts.extend(child.get("data", {}) for child in children)
    return _documents_from_posts(source, posts)


def _collect_public_json(source: dict, user_agent: str) -> list[Document]:
    posts: list[dict[str, Any]] = []
    with httpx.Client(
        base_url=source.get("public_base_url", "https://www.reddit.com"),
        headers={"User-Agent": user_agent},
        timeout=30,
        follow_redirects=True,
    ) as client:
        for subreddit in source.get("subreddits", []):
            response = client.get(f"/r/{subreddit}/new.json", params={"limit": source.get("limit_per_subreddit", 25), "raw_json": 1})
            response.raise_for_status()
            children = response.json().get("data", {}).get("children", [])
            posts.extend(child.get("data", {}) for child in children)
    return _documents_from_posts(source, posts)


def _documents_from_fallback(source: dict) -> list[Document]:
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return []
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _documents_from_posts(source, payload.get("posts", []))


def _documents_from_posts(source: dict, posts: list[dict[str, Any]]) -> list[Document]:
    documents: list[Document] = []
    for post in posts:
        title = clean_html(post.get("title", ""))
        body = clean_html(post.get("selftext", ""))
        subreddit = post.get("subreddit", "unknown")
        url = post.get("url") or f"https://www.reddit.com{post.get('permalink', '')}"
        documents.append(
            Document(
                source_id=f"reddit_{subreddit}".lower(),
                source_name=f"Reddit r/{subreddit}",
                source_type=source.get("source_type", "social"),
                url=url,
                title=title,
                body=normalize_text(body),
                published_at=_from_epoch(post.get("created_utc")),
                language="en",
                raw_metadata={
                    "subreddit": subreddit,
                    "score": post.get("score"),
                    "num_comments": post.get("num_comments"),
                    "permalink": post.get("permalink"),
                    "author_redacted": True,
                },
            )
        )
    return documents


def _from_epoch(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None
