import pytest
import yaml
from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore
from cti_pipeline.reports.detections import build_sigma_hunts

def test_sigma_upgrades_logsource_classification(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()

    # 1. Insert documents and entities
    documents = [
        Document(
            source_id="news",
            source_name="News",
            source_type="news",
            url="https://example.test/advisory",
            title="Analysis",
            body="Attackers leveraged CVE-2024-3400, any.run, and 8.8.8.8.",
            language="en"
        )
    ]
    store.insert_documents(documents)

    with store.connect() as connection:
        doc_id = connection.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    entities = [
        Entity(entity_type="cve", value="CVE-2024-3400", normalized_value="CVE-2024-3400"),
        Entity(entity_type="domain", value="any.run", normalized_value="any.run"),
        Entity(entity_type="ip", value="8.8.8.8", normalized_value="8.8.8.8")
    ]
    store.insert_document_entities(doc_id, entities, evidence="Threat advisory")

    # 2. Build default context-aware rules
    raw_rules = build_sigma_hunts(store, days=1)
    rules = list(yaml.safe_load_all(raw_rules))

    assert len(rules) == 3

    rules_by_title = {r["title"]: r for r in rules}

    # Verify CVE logsources
    cve_rule = rules_by_title["Threat Hunt For CVE CVE-2024-3400"]
    assert cve_rule["logsource"]["category"] == "process_creation"
    assert cve_rule["logsource"]["product"] == "windows"
    assert "CommandLine|contains" in cve_rule["detection"]["selection"]
    assert cve_rule["detection"]["selection"]["CommandLine|contains"] == "CVE-2024-3400"

    # Verify Domain logsources
    domain_rule = rules_by_title["Threat Hunt For DOMAIN any.run"]
    assert domain_rule["logsource"]["category"] == "dns_query"
    assert domain_rule["logsource"]["product"] == "windows"
    assert "query|contains" in domain_rule["detection"]["selection"]
    assert domain_rule["detection"]["selection"]["query|contains"] == "any.run"

    # Verify IP logsources
    ip_rule = rules_by_title["Threat Hunt For IP 8.8.8.8"]
    assert ip_rule["logsource"]["category"] == "network_connection"
    assert ip_rule["logsource"]["product"] == "windows"
    assert "DestinationIp" in ip_rule["detection"]["selection"]
    assert ip_rule["detection"]["selection"]["DestinationIp"] == "8.8.8.8"


def test_sigma_upgrades_custom_overrides_and_filters(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()

    documents = [
        Document(
            source_id="news",
            source_name="News",
            source_type="news",
            url="https://example.test/advisory",
            title="Analysis",
            body="Attackers leveraged CVE-2024-3400 and any.run.",
            language="en"
        )
    ]
    store.insert_documents(documents)

    with store.connect() as connection:
        doc_id = connection.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    entities = [
        Entity(entity_type="cve", value="CVE-2024-3400", normalized_value="CVE-2024-3400"),
        Entity(entity_type="domain", value="any.run", normalized_value="any.run")
    ]
    store.insert_document_entities(doc_id, entities, evidence="Threat advisory")

    # 1. Test Logsource Overrides
    raw_rules_override = build_sigma_hunts(
        store, days=1, log_category="firewall_logs", log_product="zeek"
    )
    rules_override = list(yaml.safe_load_all(raw_rules_override))
    for r in rules_override:
        assert r["logsource"]["category"] == "firewall_logs"
        assert r["logsource"]["product"] == "zeek"

    # 2. Test Entity Types Filtering
    raw_rules_filter = build_sigma_hunts(store, days=1, entity_types={"cve"})
    rules_filter = list(yaml.safe_load_all(raw_rules_filter))
    assert len(rules_filter) == 1
    assert rules_filter[0]["title"] == "Threat Hunt For CVE CVE-2024-3400"
