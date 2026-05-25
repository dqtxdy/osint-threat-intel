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
