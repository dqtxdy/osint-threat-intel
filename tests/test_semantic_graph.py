from __future__ import annotations

import json
from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore
from cti_pipeline.graph.semantic import build_semantic_graph
from cti_pipeline.api.main import entity_semantic_graph


def test_semantic_graph_builder(monkeypatch, tmp_path):
    # Setup database path and store
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # 1. Insert documents
    docs = [
        # GitHub Security Advisory Document
        Document(
            source_id="github_advisories",
            source_name="GitHub Security Advisories",
            source_type="vendor",
            url="https://github.com/advisories/GHSA-1234-abcd-efgh",
            title="GHSA-1234-abcd-efgh - Symfonies leak",
            body="GitHub advisory details here.",
            language="en",
            raw_metadata={
                "ghsa_id": "GHSA-1234-abcd-efgh",
                "cve_id": "CVE-2026-45756",
                "severity": "medium",
                "ecosystem": "composer:symfony/symfony",
            }
        ),
        # PhishTank Document
        Document(
            source_id="phishtank",
            source_name="PhishTank",
            source_type="threat_feed",
            url="https://phishtank.org/phish_detail.php?id=9999",
            title="PhishTank 9999 - PayPal",
            body="Verified active phishing URL: http://paypal.com-update.security/login\nTarget brand: PayPal",
            language="en",
            raw_metadata={
                "phish_id": "9999",
                "target": "PayPal",
                "verified": "yes",
                "online": "yes",
                "url": "http://paypal.com-update.security/login"
            }
        ),
        # URLhaus / ThreatFox Document
        Document(
            source_id="urlhaus",
            source_name="URLhaus",
            source_type="threat_feed",
            url="https://urlhaus.abuse.ch/url/1111/",
            title="URLhaus 1111 - evil.download",
            body="Malicious URL: http://evil.download/malware.exe",
            language="en",
            raw_metadata={
                "urlhaus_id": "1111",
                "url": "http://evil.download/malware.exe",
                "threat": "malware_download",
                "tags": ["cobalt strike"]
            }
        ),
        # ThreatFox Document
        Document(
            source_id="threatfox",
            source_name="ThreatFox",
            source_type="threat_feed",
            url="https://threatfox.abuse.ch/ioc/2222/",
            title="ThreatFox - Cobalt Strike",
            body="Indicator: 192.0.2.2",
            language="en",
            raw_metadata={
                "ioc_id": "2222",
                "ioc": "192.0.2.2",
                "ioc_type": "ip:port",
                "threat_type": "botnet",
                "malware_family": "Cobalt Strike",
                "confidence": 90
            }
        ),
        # News/Social Document referencing a domain
        Document(
            source_id="security_blog",
            source_name="Security Blog",
            source_type="news",
            url="https://example.test/blog",
            title="Reference domain mentions",
            body="Mentions google.com and mitre.org as references.",
            language="en",
        )
    ]
    
    store.insert_documents(docs)

    # Resolve document IDs
    with store.connect() as conn:
        db_docs = conn.execute("SELECT id, source_id FROM documents").fetchall()
        doc_ids = {row["source_id"]: row["id"] for row in db_docs}

    # 2. Insert document entities
    store.insert_document_entities(
        doc_ids["github_advisories"],
        [
            Entity("cve", "CVE-2026-45756", "CVE-2026-45756"),
            Entity("domain", "symfony.com", "symfony.com"),
            Entity("domain", "github.com", "github.com"),
        ],
        evidence="Vulnerability CVE-2026-45756 affects symfony.com and github.com."
    )

    store.insert_document_entities(
        doc_ids["phishtank"],
        [
            Entity("domain", "paypal.com-update.security", "paypal.com-update.security"),
            Entity("ip", "192.0.2.1", "192.0.2.1"),
        ],
        evidence="Active phishing PayPal URL on paypal.com-update.security hosted at 192.0.2.1."
    )

    store.insert_document_entities(
        doc_ids["urlhaus"],
        [
            Entity("domain", "evil.download", "evil.download"),
            Entity("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
        evidence="Malware download on evil.download."
    )

    store.insert_document_entities(
        doc_ids["threatfox"],
        [
            Entity("ip", "192.0.2.2", "192.0.2.2"),
        ],
        evidence="ThreatFox Cobalt Strike botnet hosted on 192.0.2.2."
    )

    store.insert_document_entities(
        doc_ids["security_blog"],
        [
            Entity("domain", "google.com", "google.com"),
            Entity("domain", "mitre.org", "mitre.org"),
        ],
        evidence="Google search and MITRE CVE pages are references."
    )

    # 3. Test GitHub Advisories Semantics
    graph = build_semantic_graph(store, "cve", "CVE-2026-45756")
    
    # Assert nodes structure
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "selected" in node_ids
    assert "entity-advisory-GHSA-1234-abcd-efgh" in node_ids
    assert "entity-package-composer:symfony/symfony" in node_ids
    
    # Check edges and predicates
    edges = graph["edges"]
    predicates = {e["predicate"] for e in edges}
    assert "PUBLISHED" in predicates
    assert "ASSERTS" in predicates
    assert "HAS_CVE" in predicates
    assert "AFFECTS_PACKAGE" in predicates
    assert "REFERENCES_DOMAIN" in predicates

    # Check that references domains symfony.com is classified as noise/reference category
    ref_edges = [e for e in edges if e["predicate"] == "REFERENCES_DOMAIN"]
    assert len(ref_edges) > 0
    assert any(re["category"] == "noise/reference" for re in ref_edges)

    # Verify triples structure
    triples = graph["triples"]
    assert len(triples) > 0
    assert any(t["predicate"] == "AFFECTS_PACKAGE" for t in triples)
    assert any(t["subject"] == "GHSA-1234-abcd-efgh" for t in triples)

    # 4. Test PhishTank Semantics
    phish_graph = build_semantic_graph(store, "domain", "paypal.com-update.security")
    phish_edges = phish_graph["edges"]
    phish_preds = {e["predicate"] for e in phish_edges}
    assert "TARGETS_BRAND" in phish_preds
    assert "OBSERVED_PHISHING_URL" in phish_preds
    assert "HOSTED_ON_IP" in phish_preds

    # Check targets brand PayPal node exists
    phish_nodes = {n["label"] for n in phish_graph["nodes"]}
    assert "PayPal" in phish_nodes

    # 5. Test URLhaus / ThreatFox Malware Semantics
    mal_graph = build_semantic_graph(store, "domain", "evil.download")
    mal_edges = mal_graph["edges"]
    mal_preds = {e["predicate"] for e in mal_edges}
    assert "OBSERVED_MALWARE_URL" in mal_preds

    # Test ThreatFox malware family association
    tfox_graph = build_semantic_graph(store, "ip", "192.0.2.2")
    tfox_nodes = {n["label"] for n in tfox_graph["nodes"]}
    assert "Cobalt Strike" in tfox_nodes
    tfox_edges = tfox_graph["edges"]
    tfox_preds = {e["predicate"] for e in tfox_edges}
    assert "ASSOCIATED_WITH_MALWARE" in tfox_preds

    # 6. Test Noise/Reference classification for general news domains
    blog_graph = build_semantic_graph(store, "domain", "google.com")
    blog_edges = blog_graph["edges"]
    blog_preds = {e["predicate"] for e in blog_edges}
    assert "REFERENCES_DOMAIN" in blog_preds
    assert any(e["category"] == "noise/reference" for e in blog_edges if e["predicate"] == "REFERENCES_DOMAIN")

    # 7. Test Endpoint API
    api_response = entity_semantic_graph("cve", "CVE-2026-45756")
    assert "summary" in api_response
    assert "nodes" in api_response
    assert "edges" in api_response
    assert "triples" in api_response
    assert "clusters" in api_response
    assert "filters" in api_response
    assert api_response["summary"]["focus"]["value"] == "CVE-2026-45756"


def test_case_insensitive_entity_lookup(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # Insert vendor Microsoft and product Windows
    doc = Document(
        source_id="cisa_kev",
        source_name="CISA KEV",
        source_type="vendor",
        url="https://example.test",
        title="Test Title",
        body="Body mentions Microsoft Windows.",
        language="en",
        raw_metadata={
            "cveID": "CVE-2026-9999",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "knownRansomwareCampaignUse": "Known"
        }
    )
    store.insert_documents([doc])
    
    with store.connect() as conn:
        db_doc = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()
        doc_id = db_doc["id"]

    # Insert entity with exact DB case
    store.insert_document_entities(
        doc_id,
        [
            Entity("vendor", "Microsoft", "Microsoft"),
            Entity("product", "Windows", "Windows"),
            Entity("cve", "CVE-2026-9999", "CVE-2026-9999"),
        ],
        evidence="Microsoft Windows CVE-2026-9999"
    )

    # Test exact case
    g1 = build_semantic_graph(store, "vendor", "Microsoft")
    assert g1["summary"]["evidence_count"] == 1
    assert g1["summary"]["focus"]["value"] == "Microsoft"

    # Test case fallback (lowercase)
    g2 = build_semantic_graph(store, "vendor", "microsoft")
    assert g2["summary"]["evidence_count"] == 1
    assert g2["summary"]["focus"]["value"] == "Microsoft"

    # Test mixed case
    g3 = build_semantic_graph(store, "product", "wiNdOWs")
    assert g3["summary"]["evidence_count"] == 1
    assert g3["summary"]["focus"]["value"] == "Windows"


def test_platform_domain_exclusions(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    doc = Document(
        source_id="threatfox",
        source_name="ThreatFox",
        source_type="threat_feed",
        url="https://threatfox.abuse.ch/ioc/123/",
        title="ThreatFox IOC",
        body="Abuse.ch reporting threatfox.abuse.ch platform domain.",
        language="en",
        raw_metadata={
            "ioc_id": "123",
            "ioc": "threatfox.abuse.ch",
            "threat_type": "botnet",
            "malware_family": "Cobalt Strike"
        }
    )
    store.insert_documents([doc])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    store.insert_document_entities(
        doc_id,
        [
            Entity("domain", "threatfox.abuse.ch", "threatfox.abuse.ch")
        ],
        evidence="threatfox.abuse.ch is a platform domain"
    )

    # threatfox.abuse.ch should be excluded from malware ioc status, and classified as noise/reference REFERENCES_DOMAIN
    g = build_semantic_graph(store, "domain", "threatfox.abuse.ch")
    
    # Verify risk is info (or low/medium, but not malware high)
    node = next(n for n in g["nodes"] if n["id"] == "selected")
    assert node["risk_level"] == "info"

    # Verify edge predicate is REFERENCES_DOMAIN
    edges = g["edges"]
    assert any(e["predicate"] == "REFERENCES_DOMAIN" and e["category"] == "noise/reference" for e in edges)


def test_path_artifact_exclusions(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    doc = Document(
        source_id="threatfox",
        source_name="ThreatFox",
        source_type="threat_feed",
        url="https://example.test",
        title="ThreatFox IOC",
        body="Mentions script bin.sh as indicator.",
        language="en",
        raw_metadata={
            "ioc_id": "12345",
            "ioc": "bin.sh",
            "threat_type": "botnet"
        }
    )
    store.insert_documents([doc])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    store.insert_document_entities(
        doc_id,
        [
            Entity("domain", "bin.sh", "bin.sh")
        ],
        evidence="bin.sh is script filename"
    )

    g = build_semantic_graph(store, "domain", "bin.sh")
    node = next(n for n in g["nodes"] if n["id"] == "selected")
    assert node["risk_level"] == "info"
    
    # Check that there are no OBSERVED_IOC or OBSERVED_MALWARE_URL edges for bin.sh
    edges = g["edges"]
    preds = {e["predicate"] for e in edges}
    assert "OBSERVED_IOC" not in preds
    assert "OBSERVED_MALWARE_URL" not in preds


def test_phishtank_generic_targets_and_grouping(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # 1. Test "Other" target brand suppression
    doc_other = Document(
        source_id="phishtank",
        source_name="PhishTank",
        source_type="threat_feed",
        url="https://phishtank.org/1",
        title="PhishTank 1",
        body="Phishing page targeting other",
        language="en",
        raw_metadata={"phish_id": "1", "target": "Other", "url": "http://other-phish.test"}
    )
    store.insert_documents([doc_other])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]
    store.insert_document_entities(doc_id, [Entity("domain", "other-phish.test", "other-phish.test")], "domain other-phish.test")

    g1 = build_semantic_graph(store, "domain", "other-phish.test")
    # "Other" target brand should NOT exist in the nodes
    node_labels = {n["label"] for n in g1["nodes"]}
    assert "Other" not in node_labels
    assert "Generic" not in node_labels # Not grouped yet, because count <= 5, brand "Other" should be suppressed entirely

    # 2. Test grouping of > 5 PhishTank documents
    docs = []
    for i in range(10):
        docs.append(Document(
            source_id="phishtank",
            source_name="PhishTank",
            source_type="threat_feed",
            url=f"https://phishtank.org/{i}",
            title=f"PhishTank {i}",
            body="Phishing page targeting PayPal",
            language="en",
            raw_metadata={"phish_id": str(i), "target": "PayPal", "url": f"http://paypal-phish-{i}.test"}
        ))
    
    # Clear DB and insert all docs
    with store.connect() as conn:
        conn.execute("DELETE FROM documents")
        conn.execute("DELETE FROM document_entities")
        conn.execute("DELETE FROM entities")
        
    store.insert_documents(docs)
    
    with store.connect() as conn:
        db_docs = conn.execute("SELECT id FROM documents").fetchall()
        for idx, row in enumerate(db_docs):
            store.insert_document_entities(row["id"], [Entity("domain", "paypal-phish.test", "paypal-phish.test")], "paypal-phish.test")

    # Build semantic graph focusing on paypal-phish.test
    g2 = build_semantic_graph(store, "domain", "paypal-phish.test")
    
    # Check that a virtual document node representing the grouped PhishTank paypal campaigns is present
    doc_node_labels = [n["label"] for n in g2["nodes"] if n["kind"] == "document"]
    assert any("PayPal Campaigns" in label for label in doc_node_labels)


def test_no_negative_one_evidence_documents(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # Insert two documents with shared entities
    doc1 = Document(
        source_id="source1", source_name="Source 1", source_type="news",
        url="https://example.test/1", title="Title 1", body="Mentions Microsoft and product Windows.", language="en"
    )
    doc2 = Document(
        source_id="source2", source_name="Source 2", source_type="news",
        url="https://example.test/2", title="Title 2", body="Mentions Microsoft and product Windows.", language="en"
    )
    store.insert_documents([doc1, doc2])
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM documents").fetchall()
        dids = [r["id"] for r in rows]

    # Insert entities co-occurring in both documents
    store.insert_document_entities(dids[0], [Entity("vendor", "Microsoft", "Microsoft"), Entity("product", "Windows", "Windows")], "Microsoft Windows")
    store.insert_document_entities(dids[1], [Entity("vendor", "Microsoft", "Microsoft"), Entity("product", "Windows", "Windows")], "Microsoft Windows")

    # Query Microsoft, which should return Windows as a co-occurring entity
    g = build_semantic_graph(store, "vendor", "Microsoft")
    
    # Ensure there are no edges with evidence containing -1
    edges = g["edges"]
    assert len(edges) > 0
    for edge in edges:
        assert -1 not in edge["evidence_document_ids"]
        assert len(edge["evidence_document_ids"]) > 0


def test_source_reliability_metrics():
    from cti_pipeline.graph.semantic import get_source_reliability
    assert get_source_reliability("vendor") == "high"
    assert get_source_reliability("research") == "high"
    assert get_source_reliability("threat_feed") == "high"
    assert get_source_reliability("news") == "medium"
    assert get_source_reliability("social") == "community"


def test_focus_node_risk_propagation(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # KEV Catalog Document
    doc = Document(
        source_id="cisa_kev",
        source_name="CISA KEV",
        source_type="vendor",
        url="https://example.test",
        title="Test KEV",
        body="Vulnerability CVE-2026-1111 listed in KEV catalog.",
        language="en",
        raw_metadata={
            "cveID": "CVE-2026-1111",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "knownRansomwareCampaignUse": "Known"
        }
    )
    store.insert_documents([doc])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]

    store.insert_document_entities(
        doc_id,
        [
            Entity("cve", "CVE-2026-1111", "CVE-2026-1111")
        ],
        evidence="CVE-2026-1111 is KEV"
    )

    # CVE focus risk should be critical because it is listed in KEV
    g = build_semantic_graph(store, "cve", "CVE-2026-1111")
    focus_node = next(n for n in g["nodes"] if n["id"] == "selected")
    assert focus_node["risk_level"] == "critical"


def test_knowledge_graph_hardening_presentation_bugs(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))
    store = SQLiteStore(db_path)
    store.init_db()

    # 1. Insert CISA KEV document for Microsoft and Windows
    kev_doc = Document(
        source_id="cisa_kev",
        source_name="CISA KEV",
        source_type="vendor",
        url="https://example.test/kev",
        title="KEV Update",
        body="KEV listed Microsoft Windows vulnerability.",
        language="en",
        raw_metadata={
            "cveID": "CVE-2026-9999",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "knownRansomwareCampaignUse": "Known"
        }
    )
    store.insert_documents([kev_doc])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents LIMIT 1").fetchone()["id"]
    
    store.insert_document_entities(
        doc_id,
        [
            Entity("vendor", "Microsoft", "Microsoft"),
            Entity("product", "Windows", "Windows"),
            Entity("cve", "CVE-2026-9999", "CVE-2026-9999")
        ],
        evidence="Microsoft Windows CVE-2026-9999"
    )

    # Test vendor Microsoft takeaway
    g_vendor = build_semantic_graph(store, "vendor", "Microsoft")
    assert "Vulnerability Microsoft" not in g_vendor["summary"]["analyst_takeaway"]
    assert "Vendor Microsoft" in g_vendor["summary"]["analyst_takeaway"]

    # Test product Windows takeaway
    g_product = build_semantic_graph(store, "product", "Windows")
    assert "Vulnerability Windows" not in g_product["summary"]["analyst_takeaway"]
    assert "Product Windows" in g_product["summary"]["analyst_takeaway"]

    # 2. Test abuse.ch and bin.sh takeaways
    abuse_doc = Document(
        source_id="threatfox",
        source_name="ThreatFox",
        source_type="threat_feed",
        url="https://example.test/abuse",
        title="ThreatFox report",
        body="abuse.ch platform reporting IOC.",
        language="en",
        raw_metadata={
            "ioc": "abuse.ch",
            "threat_type": "botnet"
        }
    )
    bin_doc = Document(
        source_id="urlhaus",
        source_name="URLhaus",
        source_type="threat_feed",
        url="https://example.test/bin",
        title="URLhaus report",
        body="Mentions script bin.sh in URL.",
        language="en",
        raw_metadata={
            "url": "https://malicious.test/bin.sh"
        }
    )
    store.insert_documents([abuse_doc, bin_doc])
    
    with store.connect() as conn:
        rows = conn.execute("SELECT id, source_id FROM documents").fetchall()
        doc_ids = {r["source_id"]: r["id"] for r in rows}

    store.insert_document_entities(doc_ids["threatfox"], [Entity("domain", "abuse.ch", "abuse.ch")], "abuse.ch")
    store.insert_document_entities(doc_ids["urlhaus"], [Entity("domain", "bin.sh", "bin.sh")], "bin.sh")

    g_abuse = build_semantic_graph(store, "domain", "abuse.ch")
    assert "Malicious infrastructure" not in g_abuse["summary"]["analyst_takeaway"]
    assert "CTI platform" in g_abuse["summary"]["analyst_takeaway"]

    g_bin = build_semantic_graph(store, "domain", "bin.sh")
    assert "Malicious infrastructure" not in g_bin["summary"]["analyst_takeaway"]
    assert "script/path artifact" in g_bin["summary"]["analyst_takeaway"]

    # 3. Test actual IOC gets malware/IOC takeaway
    ioc_doc = Document(
        source_id="threatfox",
        source_name="ThreatFox",
        source_type="threat_feed",
        url="https://example.test/ioc",
        title="ThreatFox IOC",
        body="IOC 45.155.69.173 detected.",
        language="en",
        raw_metadata={
            "ioc": "45.155.69.173",
            "threat_type": "botnet"
        }
    )
    store.insert_documents([ioc_doc])
    with store.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents WHERE source_id='threatfox' ORDER BY id DESC LIMIT 1").fetchone()["id"]
    store.insert_document_entities(doc_id, [Entity("ip", "45.155.69.173", "45.155.69.173")], "45.155.69.173")

    g_ioc = build_semantic_graph(store, "ip", "45.155.69.173")
    assert "Malicious infrastructure" in g_ioc["summary"]["analyst_takeaway"]

    # 4. Test grouped PhishTank graph source_count and weebly.com abused hosting platform takeaway
    pt_docs = []
    for i in range(10):
        pt_docs.append(Document(
            source_id="phishtank",
            source_name="PhishTank",
            source_type="threat_feed",
            url=f"https://phishtank.test/{i}",
            title=f"PhishTank report {i}",
            body="Phishing observed on weebly.com.",
            language="en",
            raw_metadata={
                "phish_id": str(i),
                "target": "PayPal",
                "url": f"http://weebly.com/pay-{i}"
            }
        ))
    store.insert_documents(pt_docs)
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM documents WHERE source_id='phishtank'").fetchall()
        for r in rows:
            store.insert_document_entities(r["id"], [Entity("domain", "weebly.com", "weebly.com")], "weebly.com")

    g_weebly = build_semantic_graph(store, "domain", "weebly.com")
    assert g_weebly["summary"]["source_count"] == 1
    assert "threat_feed" in g_weebly["summary"]["caveats"] or any(t == "threat_feed" for t in g_weebly["filters"]["source_types"])
    assert "abused hosting platform" in g_weebly["summary"]["analyst_takeaway"]

    # 5. High-fanout vendor Microsoft aggregation
    high_docs = []
    for i in range(15):
        high_docs.append(Document(
            source_id=f"cisa_kev_agg_{i}",
            source_name="CISA KEV",
            source_type="vendor",
            url=f"https://example.test/kev/{i}",
            title=f"KEV Vulnerability {i}",
            body=f"Vulnerability CVE-2026-80{i:02d} affecting Windows.",
            language="en",
            raw_metadata={
                "cveID": f"CVE-2026-80{i:02d}",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "knownRansomwareCampaignUse": "Known"
            }
        ))
    store.insert_documents(high_docs)
    with store.connect() as conn:
        rows = conn.execute("SELECT id, source_id FROM documents WHERE source_id LIKE 'cisa_kev_agg_%'").fetchall()
        for r in rows:
            i_str = r["source_id"].split("_")[-1]
            i = int(i_str)
            store.insert_document_entities(
                r["id"],
                [
                    Entity("vendor", "Microsoft", "Microsoft"),
                    Entity("product", "Windows", "Windows"),
                    Entity("cve", f"CVE-2026-80{i:02d}", f"CVE-2026-80{i:02d}")
                ],
                f"Microsoft Windows CVE-2026-80{i:02d}"
            )

    g_agg = build_semantic_graph(store, "vendor", "Microsoft")
    assert g_agg["summary"]["aggregation_applied"] is True
    assert g_agg["summary"]["displayed_evidence_count"] == 12
    for t in g_agg["triples"]:
        assert len(t["evidence"]) > 0

    # 6. symfony.com focus risk is info, deduplicated package names, node count <= 30
    sf_docs = []
    for i in range(3):
        sf_docs.append(Document(
            source_id=f"github_advisories_sf_{i}",
            source_name="GitHub Security Advisories",
            source_type="vendor",
            url=f"https://github.com/advisories/GHSA-sf-{i}",
            title=f"Advisory {i} for Symfony",
            body="Mentions symfony.com and Composer package symfony/html-sanitizer.",
            language="en",
            raw_metadata={
                "ghsa_id": f"GHSA-sf-{i}",
                "cve_id": f"CVE-2026-70{i:02d}",
                "severity": "medium",
                "ecosystem": "composer:symfony/html-sanitizer, composer:symfony/html-sanitizer"
            }
        ))
    store.insert_documents(sf_docs)
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM documents WHERE source_id LIKE 'github_advisories_sf_%'").fetchall()
        for r in rows:
            store.insert_document_entities(
                r["id"],
                [
                    Entity("domain", "symfony.com", "symfony.com"),
                    Entity("package", "composer:symfony/html-sanitizer", "composer:symfony/html-sanitizer")
                ],
                "symfony.com composer:symfony/html-sanitizer"
            )

    g_sf = build_semantic_graph(store, "domain", "symfony.com")
    selected_node = next(n for n in g_sf["nodes"] if n["id"] == "selected")
    assert selected_node["risk_level"] == "info"
    assert len(g_sf["nodes"]) <= 30
    preds = {e["predicate"] for e in g_sf["edges"]}
    assert "AFFECTS_PACKAGE" in preds
    assert "REFERENCES_DOMAIN" in preds

    g_pkg = build_semantic_graph(store, "package", "composer:symfony/html-sanitizer")
    assert g_pkg["summary"]["analyst_takeaway"].count("composer:symfony/html-sanitizer") == 1

    # 7. Assert url is None or string for all nodes in all generated graphs so far
    for g in (g_vendor, g_product, g_abuse, g_bin, g_ioc, g_weebly, g_agg, g_sf, g_pkg):
        for n in g["nodes"]:
            assert n.get("url") is None or isinstance(n.get("url"), str)

    # 8. Test bin.sh URLhaus path case compact mode and relationship semantics consistency
    bin_docs = []
    for i in range(10):
        bin_docs.append(Document(
            source_id=f"urlhaus_bin_{i}",
            source_name="URLhaus",
            source_type="threat_feed",
            url=f"https://example.test/bin/{i}",
            title=f"URLhaus report for bin.sh {i}",
            body=f"Malicious URL: http://192.0.2.1{i:02d}/bin.sh",
            language="en",
            raw_metadata={
                "urlhaus_id": str(100 + i),
                "url": f"http://192.0.2.1{i:02d}/bin.sh",
                "threat": "malware_download",
                "tags": ["agent tesla"]
            }
        ))
    store.insert_documents(bin_docs)
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM documents WHERE source_id LIKE 'urlhaus_bin_%'").fetchall()
        for i, r in enumerate(rows):
            store.insert_document_entities(
                r["id"],
                [
                    Entity("domain", "bin.sh", "bin.sh"),
                    Entity("ip", f"192.0.2.1{i:02d}", f"192.0.2.1{i:02d}")
                ],
                f"bin.sh hosted on 192.0.2.1{i:02d}"
            )

    g_bin_test = build_semantic_graph(store, "domain", "bin.sh")
    
    # Assert bin.sh itself does not have OBSERVED_MALWARE_URL edge, and has at least one edge connected to selected focus node
    bin_edges = [e for e in g_bin_test["edges"] if e["source"] == "selected" or e["target"] == "selected"]
    assert len(bin_edges) >= 1
    for e in bin_edges:
        assert e["predicate"] != "OBSERVED_MALWARE_URL"
        assert len(e["evidence_document_ids"]) > 0
        
    # Assert compaction was applied
    assert len(g_bin_test["nodes"]) < 30
    assert len(g_bin_test["edges"]) < 35
    
    # Assert grouped nodes preserve non-empty evidence_document_ids
    grouped_hosts_node = next((n for n in g_bin_test["nodes"] if "Grouped URLhaus Hosts" in n["label"]), None)
    assert grouped_hosts_node is not None
    grouped_edges = [e for e in g_bin_test["edges"] if e["source"] == grouped_hosts_node["id"] or e["target"] == grouped_hosts_node["id"]]
    assert len(grouped_edges) > 0
    for e in grouped_edges:
        assert len(e["evidence_document_ids"]) > 0

    # 9. Test abuse.ch platform focus compact mode visual aggregation
    abuse_docs = []
    for i in range(10):
        abuse_docs.append(Document(
            source_id=f"threatfox_abuse_{i}",
            source_name="ThreatFox",
            source_type="threat_feed",
            url=f"https://example.test/abuse/{i}",
            title=f"ThreatFox report {i}",
            body=f"abuse.ch platform reporting IOC ip 192.0.3.{i}.",
            language="en",
            raw_metadata={
                "ioc": f"192.0.3.{i}",
                "threat_type": "botnet"
            }
        ))
    store.insert_documents(abuse_docs)
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM documents WHERE source_id LIKE 'threatfox_abuse_%'").fetchall()
        for i, r in enumerate(rows):
            store.insert_document_entities(
                r["id"],
                [
                    Entity("domain", "abuse.ch", "abuse.ch"),
                    Entity("ip", f"192.0.3.{i}", f"192.0.3.{i}")
                ],
                f"abuse.ch reported IOC 192.0.3.{i}"
            )

    g_abuse_test = build_semantic_graph(store, "domain", "abuse.ch")
    # Assert compaction
    assert len(g_abuse_test["nodes"]) < 30
    assert len(g_abuse_test["edges"]) < 35
