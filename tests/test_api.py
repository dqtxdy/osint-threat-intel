from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore


def test_api_overview_and_exports(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()
    store.insert_documents(
        [
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/cve",
                title="CVE-2024-3400",
                body="CVE-2024-3400 observed with T1190.",
                language="en",
            )
        ]
    )
    with store.connect() as connection:
        document_id = connection.execute("SELECT id FROM documents").fetchone()["id"]
    store.insert_document_entities(
        document_id,
        [
            Entity("cve", "CVE-2024-3400", "CVE-2024-3400"),
            Entity("attack_technique", "T1190", "T1190"),
        ],
        evidence="CVE-2024-3400 observed with T1190.",
    )

    from cti_pipeline.api.main import export_stix, health, overview, priorities, report, source_coverage

    assert health()["status"] == "ok"
    assert overview(days=3650)["counts"]["documents"] == 1
    assert overview(days=3650)["source_coverage"]["sources"] == 1
    assert source_coverage(days=3650)["type_mix"][0]["name"] == "structured_feed"
    assert priorities(days=3650)[0]["value"] in {"CVE-2024-3400", "T1190"}
    assert export_stix(days=3650)["type"] == "bundle"
    cve_report = report(days=3650, entity_type="cve")
    assert "Scoped Threat Intelligence Report - cve Entities" in cve_report
    assert "`cve` `CVE-2024-3400`" in cve_report
