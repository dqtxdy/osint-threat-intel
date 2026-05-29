from cti_pipeline.collectors.github_advisories import collect_github_advisories


def test_github_advisories_collector_uses_fallback(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    # Use invalid URL to force fallback
    source = {
        "id": "github_advisories",
        "name": "GitHub Security Advisories",
        "source_type": "vendor",
        "limit": 2,
        "api_url": "https://invalid.localhost/advisories",
        "fallback_path": "data/sample_github_advisories.json",
    }

    documents = collect_github_advisories(source)
    assert len(documents) == 2
    assert documents[0].source_name == "GitHub Security Advisories"
    assert documents[0].source_type == "vendor"
    assert "GHSA ID:" in documents[0].body
    assert "github.com/advisories" in documents[0].url
    assert collect_github_advisories(source, allow_fallback=False) == []
