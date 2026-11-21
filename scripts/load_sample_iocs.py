"""Ornek IOC zinciri verisini Neo4j bilgi grafigine yukler.

Kullanim:
    python scripts/load_sample_iocs.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_FILE = ROOT / "data/samples/sample_ioc_chain.json"


def main() -> None:
    load_dotenv(ROOT / ".env")
    uri = os.getenv("NEO4J_URI")
    user = os.getenv("NEO4J_USER")
    password = os.getenv("NEO4J_PASSWORD")

    if not uri or not user or not password:
        raise RuntimeError("NEO4J_URI, NEO4J_USER ve NEO4J_PASSWORD tanimli olmali.")

    payload = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
    entities = payload.get("entities", [])
    relationships = payload.get("relationships", [])

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()
        with driver.session() as session:
            if entities:
                session.run(
                    """
                    UNWIND $rows AS row
                    MERGE (e:Entity {key: row.key})
                    SET e.name = row.name,
                        e.type = row.type,
                        e.description = row.description,
                        e.external_id = row.external_id,
                        e.source = row.source,
                        e.confidence = row.confidence
                    """,
                    rows=entities,
                )

            if relationships:
                session.run(
                    """
                    UNWIND $rows AS row
                    MATCH (a:Entity {key: row.source_key})
                    MATCH (b:Entity {key: row.target_key})
                    MERGE (a)-[r:RELATED {type: row.rel_type}]->(b)
                    SET r.source = row.source,
                        r.confidence = row.confidence,
                        r.predicted = row.predicted
                    """,
                    rows=relationships,
                )

        print(f"Yuklenen ornek IOC dugumu: {len(entities)}, iliski: {len(relationships)}")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
