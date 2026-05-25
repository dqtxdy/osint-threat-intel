from __future__ import annotations

import hashlib
import re

from bs4 import BeautifulSoup


WHITESPACE_RE = re.compile(r"\s+")


def clean_html(value: str | None) -> str:
    if not value:
        return ""
    text = BeautifulSoup(value, "html.parser").get_text(" ")
    return normalize_text(text)


def normalize_text(value: str) -> str:
    return WHITESPACE_RE.sub(" ", value).strip()


def content_hash(title: str, body: str) -> str:
    normalized = normalize_text(f"{title}\n{body}").lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

