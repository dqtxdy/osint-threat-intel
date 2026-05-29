from cti_pipeline.collectors.x import collect_x


def test_x_collector_uses_fallback_without_token(monkeypatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_BEARER_TOKEN", raising=False)
    documents = collect_x(
        {
            "id": "x_security",
            "name": "X Cybersecurity Search",
            "source_type": "social",
            "fallback_path": "data/sample_x_security.json",
        }
    )

    assert len(documents) == 3
    assert {document.language for document in documents} == {"en", "fr", "ja"}
    assert documents[0].source_name == "X Cybersecurity Search"
    assert documents[0].url.startswith("https://x.com/i/web/status/")


def test_x_collector_skips_without_token_in_live_only(monkeypatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_BEARER_TOKEN", raising=False)

    assert collect_x({"id": "x_security", "name": "X Cybersecurity Search"}, allow_fallback=False) == []
