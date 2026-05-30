from cti_pipeline.extractors.entities import extract_entities


def test_extracts_core_security_entities():
    text = """
    CVE-2024-3400 exploitation was observed with T1190.
    Callback URL: https://evil.example.com/a
    Hash: e3b0c44298fc1c149afbf4c8996fb924
    Ignore private IP 10.0.0.1 but keep 8.8.8.8.
    Defanged IOC: hxxps[:]//payload-server[.]example[.]net/dropper
    Standalone domain: c2.example.org
    """

    entities = {(item.entity_type, item.normalized_value) for item in extract_entities(text)}

    assert ("cve", "CVE-2024-3400") in entities
    assert ("attack_technique", "T1190") in entities
    assert ("url", "https://evil.example.com/a") in entities
    assert ("domain", "example.com") in entities
    assert ("url", "https://payload-server.example.net/dropper") in entities
    assert ("domain", "example.net") in entities
    assert ("domain", "example.org") in entities
    assert ("md5", "e3b0c44298fc1c149afbf4c8996fb924") in entities
    assert ("ip", "8.8.8.8") in entities
    assert ("ip", "10.0.0.1") not in entities


def test_extractor_valid_invalid_technique_ids():
    text = """
    We observed execution of T1059 and T1562.001 which are valid.
    However, T0008.000 and T9999.999 are completely invalid and should be ignored.
    """
    entities = {(item.entity_type, item.normalized_value) for item in extract_entities(text)}

    assert ("attack_technique", "T1059") in entities
    assert ("attack_technique", "T1562.001") in entities
    assert ("attack_technique", "T0008.000") not in entities
    assert ("attack_technique", "T9999.999") not in entities

