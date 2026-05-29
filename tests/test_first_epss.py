from cti_pipeline.enrichment.first_epss import enrich_epss_batch


def test_first_epss_enrichment_uses_fallback():
    # Use invalid URL to force fallback
    source = {
        "id": "first_epss",
        "name": "FIRST EPSS",
        "api_url": "https://invalid.localhost/epss",
        "fallback_path": "data/sample_epss.json",
    }
    
    cves = ["CVE-2024-3400", "CVE-2024-3094", "CVE-INVALID"]
    results = enrich_epss_batch(cves, source, allow_fallback=True)
    
    assert "CVE-2024-3400" in results
    assert results["CVE-2024-3400"]["epss"] == "0.9328"
    assert results["CVE-2024-3400"]["percentile"] == "0.9984"
    
    assert "CVE-2024-3094" in results
    assert "CVE-INVALID" not in results
    
    results_no_fallback = enrich_epss_batch(cves, source, allow_fallback=False)
    assert not results_no_fallback
