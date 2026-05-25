from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from cti_pipeline.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True)
class DistributionItem:
    name: str
    count: int
    share: float


@dataclass(frozen=True)
class SourceMixItem:
    source_id: str
    source_name: str
    source_type: str
    language: str
    documents: int
    last_seen: str | None
    reliability: str


@dataclass(frozen=True)
class SourceCoverage:
    window_days: int
    score: int
    posture: str
    documents: int
    sources: int
    source_types: int
    languages: int
    social_documents: int
    trusted_documents: int
    source_mix: list[SourceMixItem]
    type_mix: list[DistributionItem]
    language_mix: list[DistributionItem]
    gaps: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_source_coverage(store: SQLiteStore, days: int = 7) -> SourceCoverage:
    documents = store.recent_documents(days=days, limit=5000)
    total_documents = len(documents)
    source_counts: dict[str, dict[str, Any]] = {}
    type_counts: dict[str, int] = {}
    language_counts: dict[str, int] = {}

    for document in documents:
        source_id = str(document["source_id"])
        source_type = str(document["source_type"] or "unknown")
        language = str(document["language"] or "unknown")
        last_seen = document["published_at"] or document["collected_at"]

        type_counts[source_type] = type_counts.get(source_type, 0) + 1
        language_counts[language] = language_counts.get(language, 0) + 1

        source = source_counts.setdefault(
            source_id,
            {
                "source_id": source_id,
                "source_name": document["source_name"],
                "source_type": source_type,
                "language": language,
                "documents": 0,
                "last_seen": last_seen,
            },
        )
        source["documents"] += 1
        if last_seen and (source["last_seen"] is None or last_seen > source["last_seen"]):
            source["last_seen"] = last_seen

    source_mix = [
        SourceMixItem(
            source_id=item["source_id"],
            source_name=item["source_name"],
            source_type=item["source_type"],
            language=item["language"],
            documents=int(item["documents"]),
            last_seen=item["last_seen"],
            reliability=_source_reliability(item["source_type"]),
        )
        for item in source_counts.values()
    ]
    source_mix.sort(key=lambda item: (-item.documents, item.source_type, item.source_name))

    source_count = len(source_mix)
    source_type_count = len(type_counts)
    language_count = len(language_counts)
    social_documents = type_counts.get("social", 0)
    trusted_documents = sum(
        count for source_type, count in type_counts.items() if source_type in {"structured_feed", "cert", "vendor"}
    )

    score = _coverage_score(
        documents=total_documents,
        sources=source_count,
        source_types=source_type_count,
        languages=language_count,
        social_documents=social_documents,
        non_social_documents=total_documents - social_documents,
        trusted_documents=trusted_documents,
    )
    gaps = _coverage_gaps(total_documents, source_count, type_counts, language_count, social_documents, trusted_documents)
    recommendations = _recommendations(gaps)

    return SourceCoverage(
        window_days=days,
        score=score,
        posture=_posture(score),
        documents=total_documents,
        sources=source_count,
        source_types=source_type_count,
        languages=language_count,
        social_documents=social_documents,
        trusted_documents=trusted_documents,
        source_mix=source_mix,
        type_mix=_distribution(type_counts, total_documents),
        language_mix=_distribution(language_counts, total_documents),
        gaps=gaps,
        recommendations=recommendations,
    )


def _coverage_score(
    *,
    documents: int,
    sources: int,
    source_types: int,
    languages: int,
    social_documents: int,
    non_social_documents: int,
    trusted_documents: int,
) -> int:
    if documents == 0:
        return 0
    score = 0
    score += min(25, documents * 2)
    score += min(25, sources * 6)
    score += min(20, source_types * 7)
    score += min(15, languages * 7)
    if social_documents and non_social_documents:
        score += 10
    elif non_social_documents:
        score += 6
    elif social_documents:
        score += 3
    if trusted_documents:
        score += 5
    return min(100, score)


def _coverage_gaps(
    documents: int,
    sources: int,
    type_counts: dict[str, int],
    languages: int,
    social_documents: int,
    trusted_documents: int,
) -> list[str]:
    gaps: list[str] = []
    if documents == 0:
        return ["No documents are available in this time window."]
    if sources < 4:
        gaps.append("Fewer than four distinct OSINT sources are represented.")
    if len(type_counts) < 3:
        gaps.append("Source mix has fewer than three source categories.")
    if languages < 2:
        gaps.append("Linguistic diversity is limited to one language or unknown language content.")
    if not social_documents:
        gaps.append("Community/social discussion is missing, reducing early-warning coverage.")
    if not trusted_documents:
        gaps.append("Trusted structured, CERT, or vendor sources are missing.")
    if "news" not in type_counts:
        gaps.append("Security news sources are missing from the current window.")
    return gaps


def _recommendations(gaps: list[str]) -> list[str]:
    if not gaps:
        return ["Maintain the current source mix and monitor for source drift before presentation."]
    recommendations: list[str] = []
    for gap in gaps:
        if "Fewer than four" in gap:
            recommendations.append("Add at least two independent feeds beyond the current strongest source.")
        elif "fewer than three" in gap:
            recommendations.append("Balance structured feeds, security news, CERT/vendor advisories, and community discussion.")
        elif "Linguistic diversity" in gap:
            recommendations.append("Enable multilingual feeds such as CERT-FR and JPCERT/CC, then show language coverage in the dashboard.")
        elif "Community/social" in gap:
            recommendations.append("Collect Reddit security communities or another approved public discussion source.")
        elif "Trusted structured" in gap:
            recommendations.append("Include CISA KEV, CERT advisories, or vendor advisories before escalating findings.")
        elif "Security news" in gap:
            recommendations.append("Collect The Hacker News, BleepingComputer, or KrebsOnSecurity to improve analyst context.")
        elif "No documents" in gap:
            recommendations.append("Run the collection pipeline with fallback data first, then refresh live sources when network access is available.")
    return _dedupe(recommendations)


def _distribution(counts: dict[str, int], total: int) -> list[DistributionItem]:
    if total == 0:
        return []
    return [
        DistributionItem(name=name, count=count, share=round(count / total, 3))
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _source_reliability(source_type: str) -> str:
    if source_type in {"structured_feed", "cert", "vendor"}:
        return "high"
    if source_type in {"news", "rss"}:
        return "medium"
    if source_type == "social":
        return "community"
    return "unknown"


def _posture(score: int) -> str:
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "strong"
    if score >= 50:
        return "developing"
    if score > 0:
        return "thin"
    return "empty"


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
