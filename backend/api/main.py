from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import sys

# src klasorunu import yoluna ekle
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src"))

from cybergraph.intelligence.queries import GraphQueryService

load_dotenv()

app = FastAPI(
    title="CyberGraph API",
    description="AI-Driven Cyber Threat Intelligence and Knowledge Graph Platform",
    version="0.1.0"
)

# --- Bagimliliklar (Dependency Injection) ---

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

# --- Pydantic Modelleri (API Cevap Formatlari) ---

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

# --- Endpoint'ler (Uc Noktalar) ---

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check(svc: GraphQueryService = Depends(get_db_service)):
    """Sistemin ve veritabaninin saglik durumunu kontrol eder."""
    return svc.health()

@app.get("/search", response_model=list[EntityResponse], tags=["Search"])
def search_entities(q: str, limit: int = 10, svc: GraphQueryService = Depends(get_db_service)):
    """Isim veya ID'ye gore tehdit varligi arar."""
    results = svc.search_entities(q, limit=limit)
    return [EntityResponse(key=e.key, name=e.name, type=e.type, description=e.description) for e in results]

@app.get("/entities/{key}", response_model=EntityResponse, tags=["Entities"])
def get_entity(key: str, svc: GraphQueryService = Depends(get_db_service)):
    """Belirli bir varligin detaylarini getirir (orn: G0016)."""
    entity = svc.get_entity(key)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    return EntityResponse(key=entity.key, name=entity.name, type=entity.type, description=entity.description)

@app.get("/entities/{key}/relationships", response_model=list[RelationshipResponse], tags=["Relationships"])
def get_relationships(key: str, rel_type: Optional[str] = None, svc: GraphQueryService = Depends(get_db_service)):
    """Bir varligin giden iliskilerini getirir. Istege bagli olarak rel_type ile filtrelenebilir."""
    rels = svc.get_outgoing_relationships(key, rel_type=rel_type)
    return [
        RelationshipResponse(
            source_key=r.source_key, source_name=r.source_name, rel_type=r.rel_type,
            target_key=r.target_key, target_name=r.target_name, target_type=r.target_type
        ) for r in rels
    ]
