from cti_pipeline.enrichment.attack import enrich_attack_technique
from cti_pipeline.enrichment.nvd import _parse_nvd_cve, enrich_cve


def test_enriches_cve_from_fallback():
    payload = enrich_cve(
        "CVE-2024-3400",
        {
            "api_url": "https://invalid.localhost/nvd",
            "fallback_path": "data/sample_nvd_cves.json",
        },
    )

    assert payload is not None
    assert payload["severity"] == "CRITICAL"
    assert payload["cvss_score"] == 10.0


def test_enriches_attack_technique_from_fallback():
    payload = enrich_attack_technique(
        "T1190",
        {"fallback_path": "data/sample_attack_techniques.json"},
    )

    assert payload is not None
    assert payload["name"] == "Exploit Public-Facing Application"
    assert payload["tactic"] == "Initial Access"


def test_parses_current_nvd_references_shape():
    payload = _parse_nvd_cve(
        {
            "cve": {
                "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 9.8},
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "references": [{"url": "https://example.test/advisory"}],
            }
        }
    )

    assert payload["references"] == ["https://example.test/advisory"]
    assert payload["severity"] == "CRITICAL"
