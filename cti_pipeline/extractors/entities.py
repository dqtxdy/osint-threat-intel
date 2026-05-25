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


def extract_entities(text: str) -> list[Entity]:
    entities: dict[tuple[str, str], Entity] = {}

    for match in CVE_RE.findall(text):
        _add(entities, "cve", match.upper())

    for match in IP_RE.findall(text):
        if _is_public_ip(match):
            _add(entities, "ip", match)

    for match in URL_RE.findall(text):
        cleaned = match.rstrip(".,);]")
        _add(entities, "url", cleaned)
        domain = _domain_from_url(cleaned)
        if domain:
            _add(entities, "domain", domain)

    for match in HASH_RE.findall(text):
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(match)]
        _add(entities, hash_type, match.lower())

    for match in ATTACK_TECHNIQUE_RE.findall(text):
        _add(entities, "attack_technique", match.upper())

    return sorted(entities.values(), key=lambda item: (item.entity_type, item.normalized_value))


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
    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        return None
    extracted = TLD_EXTRACTOR(host)
    if not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}".lower()
