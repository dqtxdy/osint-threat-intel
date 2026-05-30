from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
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
    strengths: list[str] = field(default_factory=list)
    watch_items: list[str] = field(default_factory=list)

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
        count for source_type, count in type_counts.items() if source_type in {"structured_feed", "cert", "vendor", "threat_feed", "research"}
    )

    type_mix = _distribution(type_counts, total_documents)
    language_mix = _distribution(language_counts, total_documents)

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

    strengths, watch_items, recommendations = _compute_nuanced_analytics(
        total_documents=total_documents,
        source_mix=source_mix,
        type_mix=type_mix,
        language_mix=language_mix,
        type_counts=type_counts,
        gaps=gaps,
        recommendations=recommendations,
    )

    gaps = watch_items

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
        type_mix=type_mix,
        language_mix=language_mix,
        gaps=gaps,
        recommendations=recommendations,
        strengths=strengths,
        watch_items=watch_items,
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
        gaps.append("Trusted structured, CERT, vendor, research, or threat-feed sources are missing.")
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
            recommendations.append("Balance structured feeds, security news, CERT/vendor advisories, threat feeds, and community discussion.")
        elif "Linguistic diversity" in gap:
            recommendations.append("Enable multilingual feeds such as CERT-FR and JPCERT/CC, then show language coverage in the dashboard.")
        elif "Community/social" in gap:
            recommendations.append("Collect Reddit security communities or another approved public discussion source.")
        elif "Trusted structured" in gap:
            recommendations.append("Include CISA KEV, CERT advisories, vendor advisories, or threat feeds before escalating findings.")
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
    if source_type in {"structured_feed", "cert", "vendor", "threat_feed", "research"}:
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


def _compute_nuanced_analytics(
    total_documents: int,
    source_mix: list[SourceMixItem],
    type_mix: list[DistributionItem],
    language_mix: list[DistributionItem],
    type_counts: dict[str, int],
    gaps: list[str],
    recommendations: list[str]
) -> tuple[list[str], list[str], list[str]]:
    strengths: list[str] = []
    watch_items: list[str] = list(gaps)
    final_recs: list[str] = list(recommendations)

    if total_documents == 0:
        return strengths, watch_items, final_recs

    # 1. English Dominance: if English share > 85%
    en_item = next((item for item in language_mix if item.name == "en"), None)
    en_share = en_item.share if en_item else 0.0
    if en_share > 0.85:
        watch_items.append(f"Linguistic bias: English content dominates the corpus ({en_share * 100:.1f}%), creating potential visibility gaps for regional threat sources.")
        final_recs.append("Expand non-English sources (e.g., CERT-FR, JPCERT/CC) to capture localized threat activity.")
        strengths.append(f"Strong English language coverage ({en_share * 100:.1f}% share).")
    elif en_share > 0:
        strengths.append(f"Diverse language portfolio: English share is stable at {en_share * 100:.1f}%.")

    # 2. Source Concentration: if top source has > 50% or top source type has > 60%
    if source_mix:
        top_source = source_mix[0]
        top_source_share = top_source.documents / total_documents
        if top_source_share > 0.5:
            watch_items.append(f"Source concentration: Top source '{top_source.source_name}' represents {top_source_share * 100:.1f}% of ingested documents, creating single-point dependency.")
            final_recs.append(f"Add alternative feeds in the same category to balance dependency on '{top_source.source_name}'.")
        else:
            strengths.append(f"Balanced feed collection: No single source dominates (top source share is {top_source_share * 100:.1f}%).")

    if type_mix:
        top_type = type_mix[0]
        if top_type.share > 0.5:
            if top_type.name == "structured_feed":
                strengths.append("Strong structured feed reliability.")
            else:
                strengths.append(f"Strong {top_type.name} feed reliability.")

            if top_type.share > 0.6:
                watch_items.append(f"Category concentration: '{top_type.name}' feeds represent {top_type.share * 100:.1f}% of the corpus, overshadowing other signal types.")
                final_recs.append(f"Diversify feed types by enabling more CERT, news, or vendor advisory sources to balance the {top_type.name} dominance.")
        else:
            strengths.append("Balanced source-type distribution across feed categories.")

    # 3. Social/Community Coverage: light if social share < 10%
    social_count = type_counts.get("social", 0)
    social_share = social_count / total_documents
    if social_share < 0.10:
        watch_items.append(f"Light social coverage: Social/community share is {social_share * 100:.1f}% (under 10%), reducing early-warning signal for exploits.")
        final_recs.append("Recommend expanding social/community sources (e.g., Reddit netsec, X security feeds).")
    else:
        strengths.append(f"Active social/community intelligence integration ({social_share * 100:.1f}% share) for early warnings.")

    # 4. Research/Vendor Coverage: light if very low (< 10% share or count < 5)
    vendor_count = type_counts.get("vendor", 0)
    research_count = type_counts.get("research", 0)
    cert_count = type_counts.get("cert", 0)
    rvc_count = vendor_count + research_count + cert_count
    rvc_share = rvc_count / total_documents
    if rvc_share < 0.10 or rvc_count < 5:
        watch_items.append(f"Light vendor/research coverage: Primary vendor reports, deep research, and CERT advisories represent only {rvc_share * 100:.1f}% of data.")
        final_recs.append("Recommend expanding research/vendor sources to increase detailed contextual analysis.")
    else:
        strengths.append(f"Strong vendor and research advisory footprint ({rvc_share * 100:.1f}% share).")

    # 5. Stale Source Warning: if important sources have not updated recently (>= 3 days latency)
    def parse_iso(dt_str: str | None) -> datetime | None:
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except Exception:
            return None

    parsed_dates = [parse_iso(s.last_seen) for s in source_mix if s.last_seen]
    valid_dates = [d for d in parsed_dates if d is not None]

    if valid_dates:
        max_date = max(valid_dates)
        for source in source_mix:
            if source.reliability == "high" or source.source_type in {"cert", "vendor", "structured_feed", "threat_feed"}:
                s_date = parse_iso(source.last_seen)
                if s_date:
                    delta_days = (max_date - s_date).days
                    if delta_days >= 3:
                        watch_items.append(f"Stale source warning: Trusted source '{source.source_name}' has not updated in the last {delta_days} days of the window.")
                        final_recs.append(f"Verify polling pipeline schedule and API keys for source '{source.source_name}'.")

    watch_items = _dedupe([w for w in watch_items if w.strip()])
    final_recs = _dedupe([r for r in final_recs if r.strip()])
    strengths = _dedupe([s for s in strengths if s.strip()])

    if watch_items:
        generic_rec = "Maintain the current source mix and monitor for source drift before presentation."
        if generic_rec in final_recs:
            final_recs.remove(generic_rec)

    if not watch_items:
        watch_items = ["No critical coverage gaps or latency items observed."]
    if not final_recs:
        final_recs = ["Maintain current polling intervals and monitor for feed changes."]

    return strengths, watch_items, final_recs
