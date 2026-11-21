from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import os
from pathlib import Path
from dotenv import load_dotenv

from cybergraph.extraction.extractor import ThreatTextExtractor
from cybergraph.intelligence.investigation import ThreatInvestigationService
from cybergraph.intelligence.queries import GraphQueryService

load_dotenv()

ROOT = Path(__file__).resolve().parents[2]

app = FastAPI(
    title="CyberGraph API",
    description="AI-Driven Cyber Threat Intelligence and Knowledge Graph Platform",
    version="0.1.0",
)


def get_db_service():
    """Her istekte veritabani baglantisini yonetir."""
    uri = os.getenv("NEO4J_URI")
    user = os.getenv("NEO4J_USER")
    password = os.getenv("NEO4J_PASSWORD")

    if not uri or not user or not password:
        raise HTTPException(status_code=500, detail="Neo4j kimlik bilgileri eksik.")

    svc = GraphQueryService(uri, user, password)
    try:
        yield svc
    finally:
        svc.close()


def get_extractor() -> ThreatTextExtractor:
    """Yerel STIX ornek verisi varsa sozluk cikariciyi yukler."""
    for candidate in (
        ROOT / "data/samples/attack_entities.json",
        ROOT / "data/samples/enterprise-attack.json",
    ):
        if candidate.exists():
            return ThreatTextExtractor.from_attack_json(candidate)
    return ThreatTextExtractor()


class HealthResponse(BaseModel):
    status: str
    nodes: int
    relationships: int


class EntityResponse(BaseModel):
    key: str
    name: str
    type: str
    description: Optional[str] = None


class RelationshipResponse(BaseModel):
    source_key: str
    source_name: str
    rel_type: str
    target_key: str
    target_name: str
    target_type: str


class InvestigateRequest(BaseModel):
    text: str
    max_neighbors_per_entity: int = 10


class ExtractedIndicatorItem(BaseModel):
    text: str
    normalized_value: str
    entity_type: str
    confidence: str
    source: str


class LinkedEntityItem(BaseModel):
    key: str
    name: str
    entity_type: str
    matched_text: str
    outgoing_count: int
    incoming_count: int
    sample_targets: list[str]


class ChainSummaryItem(BaseModel):
    anchor_key: str
    anchor_name: str
    anchor_type: str
    related_malware: list[str] = []
    related_actors: list[str] = []
    related_techniques: list[str] = []


class InvestigateResponse(BaseModel):
    summary: dict
    indicators: list[ExtractedIndicatorItem]
    linked_entities: list[LinkedEntityItem]
    unmatched_attack_mentions: list[str]
    chain_summaries: list[ChainSummaryItem] = []


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check(svc: GraphQueryService = Depends(get_db_service)):
    """Sistemin ve veritabaninin saglik durumunu kontrol eder."""
    return svc.health()


@app.get("/search", response_model=list[EntityResponse], tags=["Search"])
def search_entities(q: str, limit: int = 10, svc: GraphQueryService = Depends(get_db_service)):
    """Isim veya ID'ye gore tehdit varligi arar."""
    results = svc.search_entities(q, limit=limit)
    return [
        EntityResponse(key=e.key, name=e.name, type=e.type, description=e.description)
        for e in results
    ]


@app.get("/entities/{key}", response_model=EntityResponse, tags=["Entities"])
def get_entity(key: str, svc: GraphQueryService = Depends(get_db_service)):
    """Belirli bir varligin detaylarini getirir (orn: G0016)."""
    entity = svc.get_entity(key)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    return EntityResponse(
        key=entity.key, name=entity.name, type=entity.type, description=entity.description
    )


@app.get(
    "/entities/{key}/relationships",
    response_model=list[RelationshipResponse],
    tags=["Relationships"],
)
def get_relationships(
    key: str,
    rel_type: Optional[str] = None,
    svc: GraphQueryService = Depends(get_db_service),
):
    """Bir varligin giden iliskilerini getirir. Istege bagli olarak rel_type ile filtrelenebilir."""
    rels = svc.get_outgoing_relationships(key, rel_type=rel_type)
    return [
        RelationshipResponse(
            source_key=r.source_key,
            source_name=r.source_name,
            rel_type=r.rel_type,
            target_key=r.target_key,
            target_name=r.target_name,
            target_type=r.target_type,
        )
        for r in rels
    ]


@app.post("/investigate", response_model=InvestigateResponse, tags=["Investigation"])
def investigate_report(
    payload: InvestigateRequest,
    svc: GraphQueryService = Depends(get_db_service),
):
    """Tehdit metninden IOC/CVE ve ATT&CK varliklari cikarip bilgi grafigiyle iliskilendirir."""
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text must not be empty.")

    service = ThreatInvestigationService(extractor=get_extractor(), query_service=svc)
    report = service.investigate_text(
        payload.text, max_neighbors_per_entity=payload.max_neighbors_per_entity
    )

    return InvestigateResponse(
        summary=report.summary,
        indicators=[
            ExtractedIndicatorItem(
                text=i.text,
                normalized_value=i.normalized_value,
                entity_type=i.entity_type,
                confidence=i.confidence,
                source=i.source,
            )
            for i in report.indicators
        ],
        linked_entities=[
            LinkedEntityItem(
                key=le.key,
                name=le.name,
                entity_type=le.entity_type,
                matched_text=le.matched_text,
                outgoing_count=le.outgoing_count,
                incoming_count=le.incoming_count,
                sample_targets=le.sample_targets,
            )
            for le in report.linked_entities
        ],
        unmatched_attack_mentions=[
            m.normalized_value for m in report.unmatched_attack_mentions
        ],
        chain_summaries=[
            ChainSummaryItem(
                anchor_key=c.anchor_key,
                anchor_name=c.anchor_name,
                anchor_type=c.anchor_type,
                related_malware=list(getattr(c, "related_malware", [])),
                related_actors=list(getattr(c, "related_actors", [])),
                related_techniques=list(getattr(c, "related_techniques", [])),
            )
            for c in getattr(report, "chain_summaries", [])
        ],
    )
