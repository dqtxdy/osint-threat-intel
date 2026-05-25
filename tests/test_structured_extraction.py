import sqlite3

from cti_pipeline.extractors.structured import metadata_entities


def test_extracts_cisa_metadata_entities():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE documents (source_id TEXT, raw_metadata TEXT)")
    connection.execute(
        "INSERT INTO documents VALUES (?, ?)",
        (
            "cisa_kev",
            '{"cveID":"CVE-2024-3400","vendorProject":"Palo Alto Networks","product":"PAN-OS","knownRansomwareCampaignUse":"Unknown"}',
        ),
    )
    row = connection.execute("SELECT * FROM documents").fetchone()

    entities = {(entity.entity_type, entity.normalized_value) for entity in metadata_entities(row)}

    assert ("vendor", "Palo Alto Networks") in entities
    assert ("product", "PAN-OS") in entities
    assert ("kev_catalog", "CVE-2024-3400") in entities
    assert ("ransomware_use", "Unknown") in entities
