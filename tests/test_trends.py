from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore


def test_entity_trends_marks_social_plus_corroborated(tmp_path):
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

    trends = store.entity_trends(days=1, limit=10)

    assert trends[0]["value"] == "CVE-2024-3400"
    assert trends[0]["source_count"] == 2
    assert trends[0]["confirmation"] == "social + corroborated"

