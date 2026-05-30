from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

from cti_pipeline.models import Entity


TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir="/tmp/cti-tldextract", suffix_list_urls=())

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
ATTACK_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
DEFANGED_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}", re.IGNORECASE)
DEFANGED_COLON_RE = re.compile(r"\[:\]|\(:\)|\{:\}", re.IGNORECASE)


def extract_entities(text: str) -> list[Entity]:
    entities: dict[tuple[str, str], Entity] = {}
    extraction_text = _refang_for_extraction(text)

    for match in CVE_RE.findall(extraction_text):
        _add(entities, "cve", match.upper())

    for match in IP_RE.findall(extraction_text):
        if _is_public_ip(match):
            _add(entities, "ip", match)

    for match in URL_RE.findall(extraction_text):
        cleaned = match.rstrip(".,);]")
        _add(entities, "url", cleaned)
        domain = _domain_from_url(cleaned)
        if domain:
            _add(entities, "domain", domain)

    for match in DOMAIN_RE.findall(extraction_text):
        domain = _domain_from_host(match)
        if domain:
            _add(entities, "domain", domain)

    for match in HASH_RE.findall(extraction_text):
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(match)]
        _add(entities, hash_type, match.lower())

    valid_techs = get_valid_techniques()
    for match in ATTACK_TECHNIQUE_RE.findall(extraction_text):
        val = match.upper()
        if valid_techs is None or val in valid_techs:
            _add(entities, "attack_technique", val)

    return sorted(entities.values(), key=lambda item: (item.entity_type, item.normalized_value))


_VALID_TECHNIQUES = None

def get_valid_techniques() -> set[str] | None:
    global _VALID_TECHNIQUES
    if _VALID_TECHNIQUES is None:
        import json
        from pathlib import Path
        catalog_paths = [
            Path(__file__).parents[2] / "data" / "attack_enterprise_techniques.json",
            Path("data/attack_enterprise_techniques.json"),
            Path(__file__).parents[2] / "data" / "sample_attack_techniques.json",
            Path("data/sample_attack_techniques.json"),
        ]
        for path in catalog_paths:
            if path.exists():
                try:
                    with path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                        _VALID_TECHNIQUES = {k.upper() for k in data.keys()}
                        break
                except Exception:
                    pass
    return _VALID_TECHNIQUES


def _add(entities: dict[tuple[str, str], Entity], entity_type: str, value: str) -> None:
    normalized = value.strip()
    key = (entity_type, normalized.lower())
    entities[key] = Entity(entity_type=entity_type, value=value, normalized_value=normalized)


def _is_public_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_link_local
    )


def _domain_from_url(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    return _domain_from_host(host)


def _domain_from_host(host: str) -> str | None:
    extracted = TLD_EXTRACTOR(host)
    if not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _refang_for_extraction(value: str) -> str:
    normalized = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    normalized = normalized.replace("hxxps[:]", "https:").replace("hxxp[:]", "http:")
    normalized = DEFANGED_DOT_RE.sub(".", normalized)
    normalized = DEFANGED_COLON_RE.sub(":", normalized)
    return normalized
