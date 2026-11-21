from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.api.main import app, get_db_service
from cybergraph.extraction.extractor import ExtractedEntity, ThreatTextExtractor
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
        res_health = client.get("/health")
        assert res_health.status_code == 200
        assert res_health.json()["nodes"] == 1962

        res_search = client.get("/search", params={"q": "APT29"})
        assert res_search.status_code == 200
        assert res_search.json()[0]["key"] == "G0016"

        res_ok = client.get("/entities/G0016")
        assert res_ok.status_code == 200
        assert res_ok.json()["name"] == "APT29"

        res_missing = client.get("/entities/UNKNOWN")
        assert res_missing.status_code == 404
    finally:
        app.dependency_overrides.clear()


@patch("backend.api.main.get_extractor")
def test_investigate_endpoint(mock_get_extractor):
    mock_extractor = MagicMock(spec=ThreatTextExtractor)
    mock_extractor.extract_all.return_value = {
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
    mock_get_extractor.return_value = mock_extractor

    mock_svc = _mock_db_service()
    app.dependency_overrides[get_db_service] = lambda: mock_svc
    try:
        res_empty = client.post("/investigate", json={"text": "   "})
        assert res_empty.status_code == 400

        res = client.post(
            "/investigate",
            json={"text": "APT29 observed with 185.220.101.4", "max_neighbors_per_entity": 5},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["summary"]["indicator_count"] == 1
        assert body["summary"]["linked_entity_count"] == 1
        assert body["linked_entities"][0]["key"] == "G0016"
    finally:
        app.dependency_overrides.clear()def test_investigate_endpoint_includes_chain_summaries():
    from cybergraph.intelligence.investigation import ChainHopSummary, InvestigationReport

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
    assert "chain_summaries" in payload
    assert len(payload["chain_summaries"]) == 1
    assert payload["chain_summaries"][0]["anchor_key"] == "IOC-DOM-001"
