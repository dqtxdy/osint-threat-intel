from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from cti_pipeline.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True)
class PriorityFinding:
    entity_type: str
    value: str
    score: int
    priority: str
    confirmation: str
    mentions: int
    source_count: int
    source_reliability: str
    analyst_verdict: str
    first_seen: str | None
    last_seen: str | None
    rationale: list[str]
    recommended_actions: list[str]
    evidence_documents: list[dict[str, Any]]
    enrichments: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_priority_findings(
    store: SQLiteStore,
    days: int = 7,
    limit: int = 25,
    entity_types: list[str] | None = None,
    normalized_value: str | None = None,
    excluded_values: list[str] | None = None,
) -> list[PriorityFinding]:
    trends = store.entity_trends(
        days=days,
        limit=limit * 3,
        entity_types=entity_types,
        normalized_value=normalized_value,
        excluded_values=excluded_values,
    )
    findings = [_score_trend(store, trend, days) for trend in trends]
    findings.sort(key=lambda finding: (-finding.score, finding.entity_type, finding.value))
    return findings[:limit]


def _score_trend(store: SQLiteStore, trend: dict[str, Any], days: int) -> PriorityFinding:
    rationale: list[str] = []
    score = 0

    mention_score = min(20, int(trend["mentions"]) * 8)
    score += mention_score
    rationale.append(f"{trend['mentions']} mention(s) contributed {mention_score} point(s).")

    source_score = min(20, int(trend["source_count"]) * 10)
    score += source_score
    rationale.append(f"{trend['source_count']} distinct source(s) contributed {source_score} point(s).")

    confirmation_score = _confirmation_score(trend["confirmation"])
    score += confirmation_score
    rationale.append(f"Confirmation status `{trend['confirmation']}` contributed {confirmation_score} point(s).")

    enrichment_score, enrichment_reason = _enrichment_score(trend)
    score += enrichment_score
    if enrichment_reason:
        rationale.append(enrichment_reason)

    evidence_documents = _evidence_documents(store, trend["type"], trend["value"])
    reliability_score, reliability_label = _source_reliability_score(evidence_documents)
    score += reliability_score
    rationale.append(f"Source reliability `{reliability_label}` contributed {reliability_score} point(s).")

    recency_score = _recency_score(trend.get("last_seen"), days)
    score += recency_score
    if recency_score:
        rationale.append(f"Recent activity contributed {recency_score} point(s).")

    score = min(100, score)
    priority = _priority_label(score)
    return PriorityFinding(
        entity_type=trend["type"],
        value=trend["value"],
        score=score,
        priority=priority,
        confirmation=trend["confirmation"],
        mentions=int(trend["mentions"]),
        source_count=int(trend["source_count"]),
        source_reliability=reliability_label,
        analyst_verdict=_analyst_verdict(priority, trend),
        first_seen=trend.get("first_seen"),
        last_seen=trend.get("last_seen"),
        rationale=rationale,
        recommended_actions=_recommended_actions(trend),
        evidence_documents=evidence_documents,
        enrichments=trend["enrichments"],
    )


def _confirmation_score(label: str) -> int:
    if label == "social + corroborated":
        return 20
    if label == "official/structured only":
        return 12
    return 4


def _enrichment_score(trend: dict[str, Any]) -> tuple[int, str]:
    if trend["type"] == "cve":
        for enrichment in trend["enrichments"]:
            if enrichment["provider"] != "nvd":
                continue
            payload = enrichment["payload"]
            score = payload.get("cvss_score")
            severity = payload.get("severity") or "UNKNOWN"
            if score is None:
                return 6, f"NVD enrichment exists with severity {severity}, contributing 6 point(s)."
            if float(score) >= 9.0:
                return 25, f"NVD severity {severity} with CVSS {score} contributed 25 point(s)."
            if float(score) >= 7.0:
                return 18, f"NVD severity {severity} with CVSS {score} contributed 18 point(s)."
            if float(score) >= 4.0:
                return 10, f"NVD severity {severity} with CVSS {score} contributed 10 point(s)."
            return 4, f"NVD severity {severity} with CVSS {score} contributed 4 point(s)."
    if trend["type"] == "attack_technique" and trend["enrichments"]:
        payload = trend["enrichments"][0]["payload"]
        name = payload.get("name", "known ATT&CK technique")
        return 10, f"Mapped to MITRE ATT&CK technique `{name}`, contributing 10 point(s)."
    return 0, ""


def _recency_score(last_seen: str | None, days: int) -> int:
    if not last_seen:
        return 0
    try:
        parsed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - parsed).days
    if age_days <= 7:
        return 10
    if age_days <= 30:
        return 7
    if age_days <= min(days, 365):
        return 3
    return 0


def _priority_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _source_reliability_score(evidence_documents: list[dict[str, Any]]) -> tuple[int, str]:
    if not evidence_documents:
        return 0, "unknown"
    weights = {
        "structured_feed": 15,
        "cert": 14,
        "vendor": 14,
        "threat_feed": 14,
        "research": 12,
        "news": 10,
        "rss": 8,
        "social": 4,
    }
    scores = [weights.get(str(document.get("source_type", "")).lower(), 6) for document in evidence_documents]
    best = max(scores)
    if best >= 14 and any(score <= 4 for score in scores):
        return 15, "high + social corroboration"
    if best >= 14:
        return 13, "high"
    if best >= 10:
        return 9, "medium"
    if best >= 4:
        return 4, "low"
    return 0, "unknown"


def _analyst_verdict(priority: str, trend: dict[str, Any]) -> str:
    if trend["type"] == "cve" and priority in {"critical", "high"}:
        return "Patch/Remediate"
    if priority == "critical":
        return "Escalate"
    if priority == "high":
        return "Investigate"
    if trend["confirmation"] == "social only":
        return "Monitor"
    if priority == "medium":
        return "Investigate"
    return "Monitor"


def _recommended_actions(trend: dict[str, Any]) -> list[str]:
    if trend["type"] == "cve":
        return [
            "Check whether affected products exist in the environment.",
            "Review vendor guidance, patch status, compensating controls, and exposure.",
            "Search logs for exploitation indicators mentioned by corroborating sources.",
        ]
    if trend["type"] == "attack_technique":
        return [
            "Review relevant MITRE ATT&CK detection guidance.",
            "Map available telemetry to the technique and identify visibility gaps.",
            "Hunt for recent activity in systems exposed to related CVEs or campaigns.",
        ]
    if trend["type"] in {"domain", "ip", "url", "md5", "sha1", "sha256"}:
        return [
            "Validate the indicator against warninglists and trusted feeds before blocking.",
            "Search network, DNS, proxy, and endpoint logs for historical sightings.",
        ]
    return [
        "Review linked source documents and decide whether this entity should be tracked.",
        "Look for corroboration from higher-confidence sources before escalating.",
    ]


def _evidence_documents(store: SQLiteStore, entity_type: str, value: str) -> list[dict[str, Any]]:
    rows = store.entity_documents(entity_type, value, limit=5)
    return [
        {
            "id": row["id"],
            "source_name": row["source_name"],
            "source_type": row["source_type"],
            "title": row["title"],
            "url": row["url"],
            "published_at": row["published_at"] or row["collected_at"],
        }
        for row in rows
    ]
