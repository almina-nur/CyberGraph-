from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    THREAT_ACTOR = "threat-actor"
    MALWARE = "malware"
    TOOL = "tool"
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    INDICATOR = "indicator"
    VULNERABILITY = "vulnerability"
    INFRASTRUCTURE = "infrastructure"


class RelationshipType(str, Enum):
    USES = "uses"
    TARGETS = "targets"
    INDICATES = "indicates"
    EXPLOITS = "exploits"
    ATTRIBUTED_TO = "attributed-to"
    MITIGATES = "mitigates"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Entity(BaseModel):
    id: str
    type: EntityType
    name: str
    description: Optional[str] = None
    external_id: Optional[str] = None
    source: str = "unknown"
    confidence: Confidence = Confidence.MEDIUM


class Relationship(BaseModel):
    source_id: str
    target_id: str
    type: RelationshipType
    description: Optional[str] = None
    source: str = "unknown"
    confidence: Confidence = Confidence.MEDIUM
    predicted: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
