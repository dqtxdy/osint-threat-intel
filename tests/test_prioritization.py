from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore


def test_priority_finding_includes_rationale_and_evidence(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()
    store.insert_documents(
        [
            Document(
                source_id="reddit_netsec",
                source_name="Reddit r/netsec",
                source_type="social",
                url="https://example.test/social",
                title="CVE-2024-3400 discussion",
                body="Social discussion about CVE-2024-3400.",
                language="en",
            ),
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/kev",
                title="CVE-2024-3400 official entry",
                body="Structured source for CVE-2024-3400.",
                language="en",
            ),
        ]
    )
    with store.connect() as connection:
        document_ids = [row["id"] for row in connection.execute("SELECT id FROM documents ORDER BY id")]

    entity = Entity("cve", "CVE-2024-3400", "CVE-2024-3400")
    for document_id in document_ids:
        store.insert_document_entities(document_id, [entity], evidence="CVE-2024-3400")
    with store.connect() as connection:
        entity_id = connection.execute("SELECT id FROM entities WHERE entity_type = 'cve'").fetchone()["id"]
    store.upsert_entity_enrichment(
        entity_id,
        "nvd",
        {"severity": "CRITICAL", "cvss_score": 10.0},
    )

    findings = build_priority_findings(store, days=1, limit=5)

    assert findings[0].value == "CVE-2024-3400"
    assert findings[0].priority in {"critical", "high"}
    assert findings[0].source_reliability == "high + social corroboration"
    assert findings[0].analyst_verdict == "Patch/Remediate"
    assert findings[0].rationale
    assert len(findings[0].evidence_documents) == 2
