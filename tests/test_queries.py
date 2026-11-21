from unittest.mock import MagicMock, patch
from cybergraph.intelligence.queries import GraphQueryService

@patch("cybergraph.intelligence.queries.GraphDatabase.driver")
def test_health_query(mock_driver):
    # Neo4j surucusunu taklit et (mock)
    mock_session = MagicMock()
    mock_driver.return_value.session.return_value.__enter__.return_value = mock_session
    
    # .single() metodunun dondurecegi sahte veriyi ayarla
    mock_session.run.return_value.single.side_effect = [{"c": 100}, {"c": 500}]
    
    svc = GraphQueryService("bolt://localhost", "user", "pass")
    health = svc.health()
    
    assert health["nodes"] == 100
    assert health["relationships"] == 500
    assert health["status"] == "ok"
