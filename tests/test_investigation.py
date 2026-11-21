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
    query_svc.search_entities.return_value = []

    service = ThreatInvestigationService(extractor=extractor, query_service=query_svc)
    report = service.investigate_text("APT29 seen with 185.220.101.4")

    assert report.summary["indicator_count"] == 1
    assert report.summary["linked_entity_count"] == 1
    assert report.linked_entities[0].key == "G0016"
    assert "uses:Cobalt Strike(S0154)" in report.linked_entities[0].sample_targets


def test_investigate_text_traces_ioc_chain():
    extractor = MagicMock(spec=ThreatTextExtractor)
    extractor.extract_all.return_value = {
        "indicators": [
            ExtractedEntity(
                text="malicious-domain.example.com",
                normalized_value="malicious-domain.example.com",
                entity_type="domain",
                source="regex-ioc-extractor",
                confidence="medium",
            )
        ],
        "attack_entities": [],
    }

    query_svc = MagicMock()
    query_svc.search_entities.return_value = [
        EntityResult(
            key="IOC-DOM-001",
            name="malicious-domain.example.com",
            type="indicator",
            description="Sample C2 domain",
            external_id="IOC-DOM-001",
        )
    ]
    query_svc.get_outgoing_relationships.side_effect = [
        [
            RelationshipResult(
                source_key="IOC-DOM-001",
                source_name="malicious-domain.example.com",
                rel_type="indicates",
                target_key="S0154",
                target_name="Cobalt Strike",
                target_type="malware",
                source="sample-ioc-feed",
            )
        ],
        [
            RelationshipResult(
                source_key="S0154",
                source_name="Cobalt Strike",
                rel_type="uses",
                target_key="T1059.001",
                target_name="PowerShell",
                target_type="attack-pattern",
                source="mitre-attack",
            )
        ],
    ]
    query_svc.get_incoming_relationships.return_value = [
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

    service = ThreatInvestigationService(extractor=extractor, query_service=query_svc)
    report = service.investigate_text("Observed malicious-domain.example.com")

    assert report.summary["chain_summary_count"] == 1
    chain = report.chain_summaries[0]
    assert chain.anchor_key == "IOC-DOM-001"
    assert "Cobalt Strike (S0154)" in chain.related_malware
    assert "APT29 (G0016)" in chain.related_actors
    assert "PowerShell (T1059.001)" in chain.related_techniques
