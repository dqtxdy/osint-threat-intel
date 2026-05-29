from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

HEADERS = {
    "User-Agent": "pentest-capstone-cti-pipeline/0.1 (+educational OSINT project)",
    "Accept": "application/json",
}


def enrich_epss_batch(cve_ids: list[str], source: dict, allow_fallback: bool = True) -> dict[str, dict[str, Any]]:
    """Query FIRST EPSS API for a batch of CVE IDs and return a dict of cve_id -> epss_payload."""
    results: dict[str, dict[str, Any]] = {}
    if not cve_ids:
        return results

    # Normalize CVE IDs to uppercase
    normalized_ids = [cve.strip().upper() for cve in cve_ids if cve.strip()]
    if not normalized_ids:
        return results

    try:
        # Batch query in chunks of 50 to avoid overly long request URLs
        chunk_size = 50
        for i in range(0, len(normalized_ids), chunk_size):
            chunk = normalized_ids[i:i+chunk_size]
            cve_param = ",".join(chunk)
            response = httpx.get(
                source.get("api_url", "https://api.first.org/data/v1/epss"),
                params={"cve": cve_param},
                headers=HEADERS,
                timeout=source.get("timeout", 8)
            )
            response.raise_for_status()
            data = response.json().get("data", [])
            
            # Format and insert results
            # EPSS returns "data" as a list of dicts: [{"cve":"CVE-2024-3400", "epss":"0.9328", ...}]
            if isinstance(data, list):
                for item in data:
                    cve = item.get("cve", "").upper()
                    if cve:
                        results[cve] = {
                            "epss": item.get("epss"),
                            "percentile": item.get("percentile"),
                            "date": item.get("date"),
                        }
            elif isinstance(data, dict):
                # Fallback check if EPSS returns data as a dict of {cve: details}
                for cve, item in data.items():
                    results[cve.upper()] = {
                        "epss": item.get("epss"),
                        "percentile": item.get("percentile"),
                        "date": item.get("date"),
                    }
    except Exception:
        pass

    # Fill in missing CVEs from fallback file if allowed
    if allow_fallback:
        fallback = _load_fallback(source.get("fallback_path"))
        for cve in normalized_ids:
            if cve not in results and cve in fallback:
                results[cve] = fallback[cve]

    return results


def _load_fallback(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}
