from datetime import datetime
from cybergraph.schemas import Entity, EntityType, Confidence, Relationship, RelationshipType

def test_entity_creation():
    e = Entity(id="T1059", type=EntityType.ATTACK_PATTERN, name="Command Execution")
    assert e.type == EntityType.ATTACK_PATTERN
    assert e.confidence == Confidence.MEDIUM
    assert e.source == "unknown"

def test_relationship_creation():
    r = Relationship(
        source_id="G0016",
        target_id="S0367",
        type=RelationshipType.USES
    )
    assert r.predicted is False
    assert r.type == RelationshipType.USES
