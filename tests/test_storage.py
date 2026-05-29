from datetime import datetime, timezone

from cti_pipeline.models import Document
from cti_pipeline.storage.sqlite_store import SQLiteStore


def test_insert_documents_updates_existing_source_url_metadata(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()
    inserted, duplicates = store.insert_documents(
        [
            Document(
                source_id="urlhaus",
                source_name="URLhaus",
                source_type="threat_feed",
                url="https://urlhaus.abuse.ch/url/1/",
                title="URLhaus 1",
                body="First Seen:",
            )
        ]
    )

    assert (inserted, duplicates) == (1, 0)

    inserted, duplicates = store.insert_documents(
        [
            Document(
                source_id="urlhaus",
                source_name="URLhaus Malware URLs",
                source_type="threat_feed",
                url="https://urlhaus.abuse.ch/url/1/",
                title="URLhaus 1",
                body="First Seen: 2026-05-29 00:00:00",
                published_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
                raw_metadata={"first_seen": "2026-05-29 00:00:00"},
            )
        ]
    )

    assert (inserted, duplicates) == (0, 1)
    rows = store.recent_documents(days=3650, limit=10)
    assert len(rows) == 1
    assert rows[0]["source_name"] == "URLhaus Malware URLs"
    assert rows[0]["published_at"].startswith("2026-05-29")
