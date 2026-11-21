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
class ChainHopSummary:
    """Bir gosterge veya varliktan yola cikarak bulunan cok adimli iliski ozeti."""

    anchor_key: str
    anchor_name: str
    anchor_type: str
    related_malware: list[str] = field(default_factory=list)
    related_actors: list[str] = field(default_factory=list)
    related_techniques: list[str] = field(default_factory=list)


@dataclass
class InvestigationReport:
    """Bir tehdit metni icin cikarim ve grafik baglantisi ozeti."""

    indicators: list[ExtractedEntity]
    linked_entities: list[LinkedAttackNode]
    unmatched_attack_mentions: list[ExtractedEntity]
    chain_summaries: list[ChainHopSummary] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class ThreatInvestigationService:
    """ThreatTextExtractor ve GraphQueryService arasinda kopru kurar."""

    def __init__(self, extractor: ThreatTextExtractor, query_service: GraphQueryService) -> None:
        self.extractor = extractor
        self.query_service = query_service

    def _find_matching_ioc_node(self, indicator: ExtractedEntity):
        """Normalize edilmis IOC degerine karsilik gelen grafik dugumunu arar."""
        candidates = self.query_service.search_entities(indicator.normalized_value, limit=5)
        for item in candidates:
            if item.type == "indicator" and (item.name or "").lower() == indicator.normalized_value.lower():
                return item
        return None

    def _resolve_source_type(self, rel, seen_sources: dict[str, Optional[str]]) -> Optional[str]:
        """Gelen iliskide kaynak dugumun tipini guvenli sekilde cozumler."""
        direct_type = getattr(rel, "source_type", None)
        if direct_type:
            return direct_type

        src_key = getattr(rel, "source_key", None)
        if not src_key:
            return None

        if src_key not in seen_sources:
            entity = self.query_service.get_entity(src_key)
            resolved = getattr(entity, "type", None) if entity is not None else None
            if resolved is None and src_key.startswith("G") and src_key[1:].isdigit():
                resolved = "intrusion-set"
            seen_sources[src_key] = resolved

        return seen_sources[src_key]

    def _build_chain_for_indicator(self, indicator: ExtractedEntity) -> Optional[ChainHopSummary]:
        """Bir IOC dugumunden zararli yazilim, aktor ve teknik zincirini cikarir."""
        ioc_node = self._find_matching_ioc_node(indicator)
        if not ioc_node:
            return None

        malware_keys: list[str] = []
        malware_labels: list[str] = []
        actor_labels: list[str] = []
        technique_labels: list[str] = []

        for rel in self.query_service.get_outgoing_relationships(ioc_node.key, limit=15):
            if rel.target_type == "malware":
                if rel.target_key not in malware_keys:
                    malware_keys.append(rel.target_key)
                    malware_labels.append(f"{rel.target_name} ({rel.target_key})")

        seen_sources: dict[str, Optional[str]] = {}
        for m_key in malware_keys[:5]:
            for inc in self.query_service.get_incoming_relationships(m_key, limit=25):
                if self._resolve_source_type(inc, seen_sources) == "intrusion-set":
                    label = f"{inc.source_name} ({inc.source_key})"
                    if label not in actor_labels:
                        actor_labels.append(label)

            for out in self.query_service.get_outgoing_relationships(m_key, limit=25):
                if out.target_type == "attack-pattern":
                    label = f"{out.target_name} ({out.target_key})"
                    if label not in technique_labels:
                        technique_labels.append(label)

        return ChainHopSummary(
            anchor_key=ioc_node.key,
            anchor_name=ioc_node.name,
            anchor_type=ioc_node.type,
            related_malware=malware_labels[:10],
            related_actors=actor_labels[:10],
            related_techniques=technique_labels[:10],
        )

    def investigate_text(self, text: str, max_neighbors_per_entity: int = 10) -> InvestigationReport:
        """Metindeki IOC ve ATT&CK varliklarini cikarir ve grafikle iliskilendirir."""
        extracted = self.extractor.extract_all(text)
        indicators = extracted["indicators"]
        attack_mentions = extracted["attack_entities"]

        linked: list[LinkedAttackNode] = []
        unmatched: list[ExtractedEntity] = []
        chain_summaries: list[ChainHopSummary] = []
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

        for ind in indicators:
            chain = self._build_chain_for_indicator(ind)
            if chain is not None:
                chain_summaries.append(chain)

        summary = {
            "indicator_count": len(indicators),
            "linked_entity_count": len(linked),
            "unmatched_mention_count": len(unmatched),
            "chain_summary_count": len(chain_summaries),
        }

        return InvestigationReport(
            indicators=indicators,
            linked_entities=linked,
            unmatched_attack_mentions=unmatched,
            chain_summaries=chain_summaries,
            summary=summary,
        )
