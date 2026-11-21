from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.api.main import app, get_db_service
from cybergraph.extraction.extractor import ExtractedEntity, ThreatTextExtractor
from cybergraph.intelligence.investigation import ChainHopSummary, InvestigationReport
from cybergraph.intelligence.queries import EntityResult, RelationshipResult

client = TestClient(app)


def _mock_db_service():
    svc = MagicMock()
    svc.health.return_value = {"status": "ok", "nodes": 1962, "relationships": 19482}
    svc.search_entities.return_value = [
        EntityResult(
            key="G0016",
            name="APT29",
            type="intrusion-set",
            description="Sample actor",
            external_id="G0016",
        )
    ]
    svc.get_entity.side_effect = lambda key: (
        EntityResult(
            key="G0016",
            name="APT29",
            type="intrusion-set",
            description="Sample actor",
            external_id="G0016",
        )
        if key == "G0016"
        else None
    )
    svc.get_outgoing_relationships.return_value = [
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
    svc.get_incoming_relationships.return_value = []
    return svc


def test_health_and_entity_endpoints():
    mock_svc = _mock_db_service()
    app.dependency_overrides[get_db_service] = lambda: mock_svc
    try:
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        r_search = client.get("/search", params={"q": "APT29"})
        assert r_search.status_code == 200
        assert len(r_search.json()) >= 1

        r_entity = client.get("/entities/G0016")
        assert r_entity.status_code == 200
        assert r_entity.json()["key"] == "G0016"
    finally:
        app.dependency_overrides.clear()


def test_investigate_endpoint():
    mock_svc = _mock_db_service()
    app.dependency_overrides[get_db_service] = lambda: mock_svc
    try:
        with patch.object(
            ThreatTextExtractor,
            "extract_all",
            return_value={
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
            },
        ):
            resp = client.post("/investigate", json={"text": "APT29 seen with 185.220.101.4"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["summary"]["indicator_count"] == 1
            assert data["summary"]["linked_entity_count"] == 1
            assert data["linked_entities"][0]["key"] == "G0016"
            assert "chain_summaries" in data
    finally:
        app.dependency_overrides.clear()


def test_investigate_endpoint_includes_chain_summaries():
    mock_svc = _mock_db_service()
    fake_report = InvestigationReport(
        indicators=[],
        linked_entities=[],
        unmatched_attack_mentions=[],
        chain_summaries=[
            ChainHopSummary(
                anchor_key="IOC-DOM-001",
                anchor_name="malicious-domain.example.com",
                anchor_type="indicator",
                related_malware=["Cobalt Strike (S0154)"],
                related_actors=["APT29 (G0016)"],
                related_techniques=["PowerShell (T1059.001)"],
            )
        ],
        summary={
            "indicator_count": 0,
            "linked_entity_count": 0,
            "unmatched_mention_count": 0,
            "chain_summary_count": 1,
        },
    )

    app.dependency_overrides[get_db_service] = lambda: mock_svc
    try:
        with patch(
            "backend.api.main.ThreatInvestigationService.investigate_text",
            return_value=fake_report,
        ):
            resp = client.post("/investigate", json={"text": "malicious-domain.example.com"})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload["chain_summaries"]) == 1
    assert payload["chain_summaries"][0]["anchor_key"] == "IOC-DOM-001"
