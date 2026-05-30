from cti_pipeline.analysis.source_coverage import build_source_coverage
from cti_pipeline.models import Document
from cti_pipeline.storage.sqlite_store import SQLiteStore


def test_source_coverage_scores_source_and_language_diversity(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()
    store.insert_documents(
        [
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/kev",
                title="CVE-2024-3400",
                body="Known exploited vulnerability.",
                language="en",
            ),
            Document(
                source_id="reddit_netsec",
                source_name="Reddit r/netsec",
                source_type="social",
                url="https://example.test/reddit",
                title="Exploit discussion",
                body="Community discussion.",
                language="en",
            ),
            Document(
                source_id="cert_fr",
                source_name="CERT-FR",
                source_type="cert",
                url="https://example.test/cert-fr",
                title="Avis de securite",
                body="Bulletin CERT.",
                language="fr",
            ),
        ]
    )

    coverage = build_source_coverage(store, days=1)

    assert coverage.documents == 3
    assert coverage.sources == 3
    assert coverage.languages == 2
    assert coverage.social_documents == 1
    assert coverage.trusted_documents == 2
    assert coverage.score >= 70
    assert not any("Linguistic diversity" in gap for gap in coverage.gaps)


def test_source_coverage_nuanced_analytics(tmp_path):
    store = SQLiteStore(tmp_path / "cti.sqlite3")
    store.init_db()
    
    # Insert 10 documents
    # 6 structured_feed documents, source_id "cisa_kev", language "en"
    # 3 social documents, source_id "reddit_netsec", language "en"
    # 1 cert document, source_id "cert_fr", language "fr"
    # Total = 10 (9 English, 1 French)
    # Top source = cisa_kev (6 documents = 60% share > 50%)
    # Top source type = structured_feed (6 documents = 60% share > 50%)
    # English share = 90% > 85%
    docs = []
    for i in range(6):
        docs.append(
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url=f"https://example.test/kev/{i}",
                title=f"Vulnerability {i}",
                body="Known exploited vulnerability.",
                language="en",
            )
        )
    for i in range(3):
        docs.append(
            Document(
                source_id="reddit_netsec",
                source_name="Reddit r/netsec",
                source_type="social",
                url=f"https://example.test/reddit/{i}",
                title=f"Discussion {i}",
                body="Community discussion.",
                language="en",
            )
        )
    docs.append(
        Document(
            source_id="cert_fr",
            source_name="CERT-FR",
            source_type="cert",
            url="https://example.test/cert-fr",
            title="Avis",
            body="Bulletin CERT.",
            language="fr",
        )
    )

    store.insert_documents(docs)
    coverage = build_source_coverage(store, days=1)

    # 1. English-heavy corpus creates a watch item
    assert any("Linguistic bias" in item for item in coverage.watch_items)
    assert any("Expand non-English sources" in item for item in coverage.recommendations)

    # 2. Top source concentration (> 50%) creates a watch item
    assert any("Source concentration" in item for item in coverage.watch_items)
    
    # 3. Top source/type concentration does not produce "balanced" wording, but honest strengths
    assert not any("Balanced source-type distribution" in item for item in coverage.strengths)
    assert not any("Balanced feed collection" in item for item in coverage.strengths)
    assert any("Strong structured feed reliability" in item for item in coverage.strengths)

    # 4. No generic maintain recommendation when watch_items exist
    generic_rec = "Maintain the current source mix and monitor for source drift before presentation."
    assert generic_rec not in coverage.recommendations

