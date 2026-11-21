"""Metin cikarimi ile Neo4j bilgi grafigini birlestiren arastirma modulu."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cybergraph.extraction.extractor import ExtractedEntity, ThreatTextExtractor
from cybergraph.intelligence.queries import GraphQueryService


@dataclass
class LinkedAttackNode:
    """Metinde eslesen ve grafikte karsiligi bulunan ATT&CK dugumu."""

    key: str
    name: str
    entity_type: str
    matched_text: str
    outgoing_count: int = 0
    incoming_count: int = 0
    sample_targets: list[str] = field(default_factory=list)


@dataclass
class InvestigationReport:
    """Bir tehdit metni icin cikarim ve grafik baglantisi ozeti."""

    indicators: list[ExtractedEntity]
    linked_entities: list[LinkedAttackNode]
    unmatched_attack_mentions: list[ExtractedEntity]
    summary: dict


class ThreatInvestigationService:
    """ThreatTextExtractor ve GraphQueryService arasinda kopru kurar."""

    def __init__(self, extractor: ThreatTextExtractor, query_service: GraphQueryService) -> None:
        self.extractor = extractor
        self.query_service = query_service

    def investigate_text(self, text: str, max_neighbors_per_entity: int = 10) -> InvestigationReport:
        extracted = self.extractor.extract_all(text)
        indicators = extracted["indicators"]
        attack_mentions = extracted["attack_entities"]

        linked: list[LinkedAttackNode] = []
        unmatched: list[ExtractedEntity] = []
        seen_keys: set[str] = set()

        for mention in attack_mentions:
            key = mention.matched_key
            if not key:
                unmatched.append(mention)
                continue
            if key in seen_keys:
                continue

            entity = self.query_service.get_entity(key)
            if entity is None:
                unmatched.append(mention)
                continue

            seen_keys.add(key)
            outgoing = self.query_service.get_outgoing_relationships(
                key, limit=max_neighbors_per_entity
            )
            incoming = self.query_service.get_incoming_relationships(
                key, limit=max_neighbors_per_entity
            )
            sample_targets = [f"{r.rel_type}:{r.target_name}({r.target_key})" for r in outgoing[:5]]

            linked.append(
                LinkedAttackNode(
                    key=entity.key,
                    name=entity.name,
                    entity_type=entity.type,
                    matched_text=mention.normalized_value,
                    outgoing_count=len(outgoing),
                    incoming_count=len(incoming),
                    sample_targets=sample_targets,
                )
            )

        summary = {
            "indicator_count": len(indicators),
            "linked_entity_count": len(linked),
            "unmatched_mention_count": len(unmatched),
        }

        return InvestigationReport(
            indicators=indicators,
            linked_entities=linked,
            unmatched_attack_mentions=unmatched,
            summary=summary,
        )
