from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from cti_pipeline.models import Document


HEADERS = {
    "User-Agent": "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)",
    "Accept": "application/json,text/plain,*/*",
}


def collect_cisa_kev(source: dict, allow_fallback: bool = True) -> list[Document]:
    payload = _load_payload(source, allow_fallback=allow_fallback)
    vulnerabilities = payload.get("vulnerabilities", [])
    documents: list[Document] = []

    for item in vulnerabilities:
        cve_id = item.get("cveID", "")
        title = f"{cve_id} - {item.get('vendorProject', '')} {item.get('product', '')}".strip()
        body_parts = [
            item.get("vulnerabilityName", ""),
            item.get("shortDescription", ""),
            f"Required action: {item.get('requiredAction', '')}",
            f"Known ransomware use: {item.get('knownRansomwareCampaignUse', '')}",
            f"Due date: {item.get('dueDate', '')}",
        ]
        documents.append(
            Document(
                source_id=source["id"],
                source_name=source["name"],
                source_type=source.get("source_type", "structured_feed"),
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                title=title,
                body="\n".join(part for part in body_parts if part),
                published_at=_parse_cisa_date(item.get("dateAdded")),
                language="en",
                raw_metadata=item,
            )
        )

    return documents


def _load_payload(source: dict, allow_fallback: bool = True) -> dict:
    urls = [source["url"], *source.get("mirror_urls", [])]
    for url in urls:
        try:
            response = httpx.get(url, timeout=30, headers=HEADERS)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            continue
    if not allow_fallback:
        return {"vulnerabilities": []}
    fallback_path = source.get("fallback_path")
    if not fallback_path:
        return {"vulnerabilities": []}
    with Path(fallback_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _parse_cisa_date(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
