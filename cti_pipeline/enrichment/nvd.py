from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx


HEADERS = {
    "User-Agent": "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)",
    "Accept": "application/json",
}


def enrich_cve(cve_id: str, source: dict, allow_fallback: bool = True) -> dict[str, Any] | None:
    fallback = _load_fallback(source.get("fallback_path")) if allow_fallback else {}
    try:
        response = httpx.get(source["api_url"], params={"cveId": cve_id}, headers=HEADERS, timeout=source.get("timeout", 8))
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if vulnerabilities:
            return _parse_nvd_cve(vulnerabilities[0])
    except httpx.HTTPError:
        pass
    return fallback.get(cve_id.upper())


def _parse_nvd_cve(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    metrics = cve.get("metrics", {})
    severity, score = _best_metric(metrics)
    references = [ref.get("url") for ref in _reference_items(cve.get("references")) if ref.get("url")]
    return {
        "description": _english_description(descriptions),
        "severity": severity,
        "cvss_score": score,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": references[:5],
    }


def _best_metric(metrics: dict[str, Any]) -> tuple[str | None, float | None]:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key) or []
        if values:
            cvss_data = values[0].get("cvssData", {})
            severity = values[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            score = cvss_data.get("baseScore")
            return severity, score
    return None, None


def _reference_items(references: Any) -> list[dict[str, Any]]:
    if isinstance(references, list):
        return [item for item in references if isinstance(item, dict)]
    if isinstance(references, dict):
        return [
            item
            for item in references.get("referenceData", [])
            if isinstance(item, dict)
        ]
    return []


def _english_description(descriptions: list[dict[str, str]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _load_fallback(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)
