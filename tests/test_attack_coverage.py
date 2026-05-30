import pytest
from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore
from cti_pipeline.reports.attack_layer import build_attack_navigator_layer

def test_build_attack_navigator_layer_coverage(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()

    # 1. Insert documents
    documents = [
        Document(
            source_id="news_source",
            source_name="News Source",
            source_type="news",
            url="https://example.test/news",
            title="Analysis of campaign",
            body="Attackers used T1190, T1562.001, and invalid T0008.000.",
            language="en"
        )
    ]
    store.insert_documents(documents)

    with store.connect() as connection:
        doc_id = connection.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    # 2. Insert 250 IP entities (non-ATT&CK) to ensure the global limit doesn't truncate
    entities = []
    for i in range(250):
        entities.append(Entity(entity_type="ip", value=f"1.1.1.{i}", normalized_value=f"1.1.1.{i}"))

    # Add ATT&CK entities
    entities.append(Entity(entity_type="attack_technique", value="T1190", normalized_value="T1190"))
    entities.append(Entity(entity_type="attack_technique", value="T1562.001", normalized_value="T1562.001"))
    entities.append(Entity(entity_type="attack_technique", value="T0008.000", normalized_value="T0008.000"))

    store.insert_document_entities(doc_id, entities, evidence="Threat intel report")

    # Call report builder
    layer = build_attack_navigator_layer(store, days=1)

    # 3. Assertions
    techniques = {t["techniqueID"]: t for t in layer["techniques"]}

    # Valid techniques must remain included
    assert "T1190" in techniques
    assert "T1562.001" in techniques

    # Invalid techniques must be excluded
    assert "T0008.000" not in techniques

    # Ignored invalid ID count must be 1
    assert layer["ignored_invalid_ids_count"] == 1

    # Enriched metadata assertion
    t1190_meta = techniques["T1190"]
    assert t1190_meta["name"] == "Exploit Public-Facing Application"
    assert "Initial Access" in t1190_meta["tactics"]
    assert t1190_meta["mention_count"] == 1
    assert t1190_meta["source_count"] == 1
    assert t1190_meta["confirmation"] == "official/structured only"
