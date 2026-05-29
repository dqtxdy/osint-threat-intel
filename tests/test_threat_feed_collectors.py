from cti_pipeline.collectors.otx import collect_otx
from cti_pipeline.collectors.phishtank import collect_phishtank
from cti_pipeline.collectors.urlhaus import collect_urlhaus, _documents_from_urls
from cti_pipeline.collectors.threatfox import collect_threatfox


def test_phishtank_collector_uses_fallback(monkeypatch):
    monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)
    documents = collect_phishtank(
        {
            "id": "phishtank",
            "name": "PhishTank Verified Active Phishing",
            "source_type": "threat_feed",
            "url": "https://data.phishtank.com/data/online-valid.json",
            "limit": 2,
            "fallback_path": "data/sample_phishtank.json",
        }
    )

    assert len(documents) == 2
    assert documents[0].source_type == "threat_feed"
    assert "Verified active phishing URL" in documents[0].body
    assert "phish_detail.php" in documents[0].url


def test_otx_collector_fallback_and_live_only(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.delenv("ALIENVAULT_OTX_API_KEY", raising=False)
    source = {
        "id": "otx",
        "name": "AlienVault OTX Pulses",
        "source_type": "threat_feed",
        "limit": 2,
        "fallback_path": "data/sample_otx_pulses.json",
    }

    documents = collect_otx(source)
    assert len(documents) == 2
    assert documents[0].source_name == "AlienVault OTX Pulses"
    assert "Indicators:" in documents[0].body
    assert collect_otx(source, allow_fallback=False) == []


def test_urlhaus_collector_uses_fallback(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    source = {
        "id": "urlhaus",
        "name": "URLhaus Malware URLs",
        "source_type": "threat_feed",
        "limit": 2,
        "fallback_path": "data/sample_urlhaus.json",
    }

    documents = collect_urlhaus(source)
    assert len(documents) == 2
    assert documents[0].source_name == "URLhaus Malware URLs"
    assert "Malicious URL:" in documents[0].body
    assert "urlhaus.abuse.ch" in documents[0].url
    assert collect_urlhaus(source, allow_fallback=False) == []


def test_urlhaus_collector_accepts_dateadded_timestamp():
    documents = _documents_from_urls(
        {
            "id": "urlhaus",
            "name": "URLhaus Malware URLs",
            "source_type": "threat_feed",
            "limit": 1,
        },
        [
            {
                "id": "3855355",
                "url": "http://payload.example/malware.exe",
                "dateadded": "2026-05-29 11:10:00",
            }
        ],
    )

    assert len(documents) == 1
    assert documents[0].published_at is not None
    assert documents[0].raw_metadata["first_seen"] == "2026-05-29 11:10:00"


def test_threatfox_collector_uses_fallback(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    source = {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "source_type": "threat_feed",
        "limit": 2,
        "fallback_path": "data/sample_threatfox.json",
    }

    documents = collect_threatfox(source)
    assert len(documents) == 2
    assert documents[0].source_name == "ThreatFox IOCs"
    assert "Indicator of Compromise (IOC):" in documents[0].body
    assert "threatfox.abuse.ch" in documents[0].url
    assert collect_threatfox(source, allow_fallback=False) == []
