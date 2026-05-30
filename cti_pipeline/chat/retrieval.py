from __future__ import annotations

import re
from typing import Any

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.extractors.entities import extract_entities
from cti_pipeline.storage.sqlite_store import SQLiteStore


STOP_WORDS = {
    "what", "where", "which", "whose", "who", "when", "how", "why", "recent", "recently",
    "about", "above", "after", "again", "against", "all", "and", "any", "are", "because",
    "been", "before", "being", "below", "between", "both", "but", "can", "cannot", "could",
    "did", "does", "doing", "down", "during", "each", "few", "for", "from", "further",
    "had", "has", "have", "having", "her", "here", "hers", "herself", "him", "himself",
    "his", "its", "itself", "know", "known", "latest", "me", "more", "most", "my", "myself",
    "nor", "off", "once", "only", "other", "ought", "our", "ours", "ourselves", "out",
    "over", "own", "same", "she", "should", "show", "some", "such", "than", "that", "the",
    "their", "theirs", "them", "themselves", "then", "there", "these", "they", "this",
    "those", "through", "too", "under", "until", "very", "was", "were", "while", "whom",
    "with", "would", "you", "your", "yours", "yourself", "yourselves", "summarize", "explain",
}


INTENT_EXPANSIONS = {
    "phishing": ["phishing", "phish", "phishtank", "credential", "brand"],
    "malware": ["malware", "ioc", "indicator", "indicators", "urlhaus", "threatfox", "hash", "loader", "stealer"],
    "ransomware": ["ransomware", "extortion", "ransomware_use"],
    "vulnerability": ["cve", "vulnerability", "vulnerabilities", "kev", "advisory", "exploit"],
}


def build_chat_context(store: SQLiteStore, question: str, days: int = 3650, limit: int = 12) -> dict[str, Any]:
    # 1. Extract entities using existing extractor
    extracted_entities = extract_entities(question)

    # 2. Extract keywords from the question for simple keyword search
    keywords = _keywords_for_question(question)

    matching_doc_scores: dict[int, int] = {}
    matching_entities: list[dict[str, Any]] = []

    with store.connect() as connection:
        # Search by extracted entities
        for ent in extracted_entities:
            rows = connection.execute(
                """
                SELECT DISTINCT de.document_id, e.entity_type, e.normalized_value
                FROM entities e
                JOIN document_entities de ON de.entity_id = e.id
                WHERE e.entity_type = ? AND e.normalized_value = ?
                """,
                (ent.entity_type, ent.normalized_value)
            ).fetchall()
            for r in rows:
                _score_document(matching_doc_scores, int(r["document_id"]), 12)
                ent_dict = {"type": r["entity_type"], "value": r["normalized_value"]}
                if ent_dict not in matching_entities:
                    matching_entities.append(ent_dict)

        # Keyword search on title/body/source_name
        if keywords:
            for kw in keywords:
                rows = connection.execute(
                    """
                    SELECT id FROM documents
                    WHERE lower(title) LIKE ?
                       OR lower(body) LIKE ?
                       OR lower(source_name) LIKE ?
                       OR lower(source_id) LIKE ?
                    """,
                    (f"%{kw}%", f"%{kw}%", f"%{kw}%", f"%{kw}%")
                ).fetchall()
                for r in rows:
                    _score_document(matching_doc_scores, int(r["id"]), 3)

        _add_intent_document_scores(connection, question, matching_doc_scores)

        # Build SQL condition based on days and retrieved doc IDs
        params: list[Any] = [f"-{days} days"]

        if matching_doc_scores:
            candidate_ids = [
                document_id
                for document_id, _score in sorted(matching_doc_scores.items(), key=lambda item: item[1], reverse=True)[:500]
            ]
            placeholders = ", ".join("?" for _ in candidate_ids)
            sql = f"""
                SELECT id, source_id, source_name, source_type, url, title, body, published_at, collected_at
                FROM documents
                WHERE datetime(COALESCE(published_at, collected_at)) >= datetime('now', ?)
                  AND id IN ({placeholders})
            """
            params.extend(candidate_ids)
        else:
            # Fallback to recent documents
            sql = """
                SELECT id, source_id, source_name, source_type, url, title, body, published_at, collected_at
                FROM documents
                WHERE datetime(COALESCE(published_at, collected_at)) >= datetime('now', ?)
                ORDER BY
                  CASE
                    WHEN source_type IN ('structured_feed', 'cert', 'vendor', 'threat_feed', 'research') THEN 0
                    WHEN source_type IN ('news', 'rss') THEN 1
                    ELSE 2
                  END ASC,
                  COALESCE(published_at, collected_at) DESC
                LIMIT ?
            """
            params.append(limit)

        doc_rows = connection.execute(sql, params).fetchall()

    if matching_doc_scores:
        doc_rows = sorted(
            doc_rows,
            key=lambda row: (
                matching_doc_scores.get(int(row["id"]), 0),
                _source_weight(row["source_type"]),
                str(row["published_at"] or row["collected_at"] or ""),
            ),
            reverse=True,
        )[:limit]

    documents = []
    for row in doc_rows:
        ent_rows = store.document_entities(row["id"])
        doc_entities = []
        for er in ent_rows:
            ent_dict = {"type": er["entity_type"], "value": er["normalized_value"]}
            doc_entities.append(ent_dict)
            if ent_dict not in matching_entities and len(matching_entities) < 30:
                matching_entities.append(ent_dict)

        documents.append({
            "id": row["id"],
            "source_id": row["source_id"],
            "source_name": row["source_name"],
            "source_type": row["source_type"],
            "url": row["url"],
            "title": row["title"],
            "published_at": row["published_at"] or row["collected_at"],
            "body_excerpt": row["body"][:1200],
            "entities": doc_entities
        })

    # Get overall source coverage/counts
    coverage = build_source_coverage(store, days=days)
    coverage_dict = coverage.to_dict()

    # Get top priority findings
    priorities = build_priority_findings(store, days=days, limit=limit)
    priorities_list = [p.to_dict() for p in priorities]

    # Get relevant trends
    trends = store.entity_trends(days=days, limit=30)

    # Get relevant source/language mix
    source_mix = [
        {
            "source_name": s["source_name"],
            "source_type": s["source_type"],
            "language": s["language"],
            "documents": s["documents"],
            "reliability": s["reliability"]
        } for s in coverage_dict.get("source_mix", [])
    ]
    language_mix = coverage_dict.get("language_mix", [])
    gaps = coverage_dict.get("gaps", [])

    return {
        "counts": {
            "documents": coverage_dict.get("documents", 0),
            "sources": coverage_dict.get("sources", 0),
            "source_types": coverage_dict.get("source_types", 0),
            "languages": coverage_dict.get("languages", 0),
        },
        "gaps": gaps,
        "source_mix": source_mix,
        "language_mix": language_mix,
        "top_priorities": priorities_list,
        "documents": documents,
        "matching_entities": matching_entities[:30],
        "trends": trends[:20]
    }


def _keywords_for_question(question: str) -> list[str]:
    lower_question = question.lower()
    words = re.findall(r"\b[a-zA-Z0-9_-]{3,40}\b", lower_question)
    keywords = [word for word in words if word not in STOP_WORDS]

    if "phish" in lower_question:
        keywords.extend(INTENT_EXPANSIONS["phishing"])
    if "malware" in lower_question or "ioc" in lower_question or "indicator" in lower_question:
        keywords.extend(INTENT_EXPANSIONS["malware"])
    if "ransomware" in lower_question:
        keywords.extend(INTENT_EXPANSIONS["ransomware"])
    if "cve" in lower_question or "vulnerab" in lower_question or "exploit" in lower_question:
        keywords.extend(INTENT_EXPANSIONS["vulnerability"])

    seen: set[str] = set()
    return [keyword for keyword in keywords if not (keyword in seen or seen.add(keyword))]


def _score_document(scores: dict[int, int], document_id: int, points: int) -> None:
    scores[document_id] = scores.get(document_id, 0) + points


def _add_intent_document_scores(connection: Any, question: str, scores: dict[int, int]) -> None:
    lower_question = question.lower()
    if "phish" in lower_question:
        rows = connection.execute(
            """
            SELECT id FROM documents
            WHERE source_id = 'phishtank'
               OR lower(source_name) LIKE '%phishtank%'
            """
        ).fetchall()
        for row in rows:
            _score_document(scores, int(row["id"]), 18)

        rows = connection.execute(
            """
            SELECT id FROM documents
            WHERE lower(title) LIKE '%phish%'
               OR lower(body) LIKE '%phish%'
            """
        ).fetchall()
        for row in rows:
            _score_document(scores, int(row["id"]), 6)

    if "malware" in lower_question or "ioc" in lower_question or "indicator" in lower_question:
        rows = connection.execute(
            """
            SELECT id FROM documents
            WHERE source_id IN ('urlhaus', 'threatfox')
               OR lower(source_name) LIKE '%urlhaus%'
               OR lower(source_name) LIKE '%threatfox%'
            """
        ).fetchall()
        for row in rows:
            _score_document(scores, int(row["id"]), 18)

        rows = connection.execute(
            """
            SELECT id FROM documents
            WHERE lower(title) LIKE '%malware%'
               OR lower(body) LIKE '%malware%'
               OR lower(body) LIKE '%indicator of compromise%'
            """
        ).fetchall()
        for row in rows:
            _score_document(scores, int(row["id"]), 6)


def _source_weight(source_type: str) -> int:
    if source_type in {"structured_feed", "cert", "vendor", "threat_feed", "research"}:
        return 3
    if source_type in {"news", "rss"}:
        return 2
    return 1
