from unittest.mock import MagicMock

from cybergraph.extraction.extractor import ExtractedEntity, ThreatTextExtractor
from cybergraph.intelligence.investigation import ThreatInvestigationService
from cybergraph.intelligence.queries import EntityResult, RelationshipResult


def test_investigate_text_links_graph_entities():
    extractor = MagicMock(spec=ThreatTextExtractor)
    extractor.extract_all.return_value = {
        "indicators": [
            ExtractedEntity(
                text="185.220.101.4",
                normalized_value="185.220.101.4",
                entity_type="ipv4",
                source="regex-ioc-extractor",
                confidence="high",
            )
        ],
        "attack_entities": [
            ExtractedEntity(
                text="apt29",
                normalized_value="apt29",
                entity_type="intrusion-set",
                matched_key="G0016",
                source="mitre-lexicon-matcher",
                confidence="medium",
            )
        ],
    }

    query_svc = MagicMock()
    query_svc.get_entity.return_value = EntityResult(
        key="G0016",
        name="APT29",
        type="intrusion-set",
        description="Sample actor",
        external_id="G0016",
    )
    query_svc.get_outgoing_relationships.return_value = [
        RelationshipResult(
            source_key="G0016",
            source_name="APT29",
            rel_type="uses",
            target_key="S0154",
            target_name="Cobalt Strike",
            target_type="malware",
            source="mitre-attack",
        )
    ]
    query_svc.get_incoming_relationships.return_value = []

    service = ThreatInvestigationService(extractor=extractor, query_service=query_svc)
    report = service.investigate_text("APT29 seen with 185.220.101.4")

    assert report.summary["indicator_count"] == 1
    assert report.summary["linked_entity_count"] == 1
    assert report.linked_entities[0].key == "G0016"
    assert "uses:Cobalt Strike(S0154)" in report.linked_entities[0].sample_targets
