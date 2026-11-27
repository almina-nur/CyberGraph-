from cybergraph.extraction.extractor import ThreatTextExtractor, defang_text


def test_defang_text():
    raw = "hxxp://evil[.]example[.]com/payload"
    assert defang_text(raw) == "http://evil.example.com/payload"


def test_defang_uppercase_scheme_in_sentence():
    raw = "Source: HXXPS://example[.]org/path"
    assert defang_text(raw) == "Source: https://example.org/path"


def test_extract_indicators_and_cve():
    extractor = ThreatTextExtractor()
    text = (
        "C2 at hxxps://c2[.]badactor[.]org/gate and 10.20.30.40 "
        "exploited cve-2024-3094 with sha256 "
        + ("a" * 64)
    )
    items = extractor.extract_indicators(text)
    found = {(i.entity_type, i.normalized_value) for i in items}

    assert ("url", "https://c2.badactor.org/gate") in found
    assert ("domain", "c2.badactor.org") in found
    assert ("ipv4", "10.20.30.40") in found
    assert ("vulnerability", "CVE-2024-3094") in found
    assert ("hash-sha256", "a" * 64) in found


def test_extract_attack_entities_from_stix_objects():
    stix_objects = [
        {
            "type": "intrusion-set",
            "name": "APT29",
            "aliases": ["APT29", "The Dukes", "Cozy Bear"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
        },
        {
            "type": "malware",
            "name": "Cobalt Strike",
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0154"}],
        },
    ]
    extractor = ThreatTextExtractor.from_attack_objects(stix_objects)
    matches = extractor.extract_attack_entities("Cozy Bear deployed Cobalt Strike.")
    keys = {m.matched_key for m in matches}

    assert "G0016" in keys
    assert "S0154" in keys
