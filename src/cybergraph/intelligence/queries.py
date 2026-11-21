"""Neo4j Cypher sorgu servisi.

FastAPI, Streamlit ve testler bu sinifi kullanir. Sorgular tek yerden
yonetilir; degisiklik oldugunda tek dosyayi guncellemek yeterlidir.
"""

from dataclasses import dataclass
from typing import Optional

from neo4j import Driver, GraphDatabase


@dataclass
class EntityResult:
    key: str
    name: str
    type: str
    description: Optional[str] = None
    external_id: Optional[str] = None


@dataclass
class RelationshipResult:
    source_key: str
    source_name: str
    rel_type: str
    target_key: str
    target_name: str
    target_type: str
    source: Optional[str] = None


class GraphQueryService:
    """Neo4j uzerinde yuksek seviye sorgu API'si."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "GraphQueryService":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ----- Saglik ve istatistik -----

    def health(self) -> dict:
        with self._driver.session() as s:
            n = s.run("MATCH (n:Entity) RETURN count(n) AS c").single()["c"]
            r = s.run("MATCH ()-[r:RELATED]->() RETURN count(r) AS c").single()["c"]
        return {"nodes": n, "relationships": r, "status": "ok"}

    def relationship_type_distribution(self) -> list[dict]:
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH ()-[r:RELATED]->()
                RETURN r.type AS type, count(*) AS count
                ORDER BY count DESC
                """
            )
            return [dict(row) for row in result]

    # ----- Arama -----

    def search_entities(self, query: str, limit: int = 10) -> list[EntityResult]:
        """Isim veya key uzerinde case-insensitive arama."""
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (e:Entity)
                WHERE toLower(e.name) CONTAINS toLower($q)
                   OR toLower(e.key) CONTAINS toLower($q)
                RETURN e.key AS key, e.name AS name, e.type AS type,
                       e.description AS description, e.external_id AS external_id
                ORDER BY
                  CASE WHEN toLower(e.name) = toLower($q) THEN 0 ELSE 1 END,
                  e.name
                LIMIT $limit
                """,
                q=query,
                limit=limit,
            )
            return [
                EntityResult(
                    key=row["key"],
                    name=row["name"],
                    type=row["type"],
                    description=row["description"],
                    external_id=row["external_id"],
                )
                for row in result
            ]

    def get_entity(self, key: str) -> Optional[EntityResult]:
        with self._driver.session() as s:
            row = s.run(
                """
                MATCH (e:Entity {key: $key})
                RETURN e.key AS key, e.name AS name, e.type AS type,
                       e.description AS description, e.external_id AS external_id
                """,
                key=key,
            ).single()
            if row is None:
                return None
            return EntityResult(
                key=row["key"],
                name=row["name"],
                type=row["type"],
                description=row["description"],
                external_id=row["external_id"],
            )

    # ----- Komsular ve iliskiler -----

    def get_outgoing_relationships(
        self, key: str, rel_type: Optional[str] = None, limit: int = 50
    ) -> list[RelationshipResult]:
        """Bir dugumun giden iliskilerini getir. rel_type verilirse filtreler."""
        cypher = """
            MATCH (a:Entity {key: $key})-[r:RELATED]->(b:Entity)
            WHERE $rel_type IS NULL OR r.type = $rel_type
            RETURN a.key AS source_key, a.name AS source_name, r.type AS rel_type,
                   b.key AS target_key, b.name AS target_name, b.type AS target_type,
                   r.source AS source
            ORDER BY r.type, b.name
            LIMIT $limit
        """
        with self._driver.session() as s:
            result = s.run(cypher, key=key, rel_type=rel_type, limit=limit)
            return [
                RelationshipResult(
                    source_key=row["source_key"],
                    source_name=row["source_name"],
                    rel_type=row["rel_type"],
                    target_key=row["target_key"],
                    target_name=row["target_name"],
                    target_type=row["target_type"],
                    source=row["source"],
                )
                for row in result
            ]

    def get_incoming_relationships(
        self, key: str, rel_type: Optional[str] = None, limit: int = 50
    ) -> list[RelationshipResult]:
        """Bir dugume gelen iliskileri getir. Ornegin: hangi aktorler bu malware'i kullaniyor?"""
        cypher = """
            MATCH (a:Entity)-[r:RELATED]->(b:Entity {key: $key})
            WHERE $rel_type IS NULL OR r.type = $rel_type
            RETURN a.key AS source_key, a.name AS source_name, r.type AS rel_type,
                   b.key AS target_key, b.name AS target_name, b.type AS target_type,
                   r.source AS source
            ORDER BY r.type, a.name
            LIMIT $limit
        """
        with self._driver.session() as s:
            result = s.run(cypher, key=key, rel_type=rel_type, limit=limit)
            return [
                RelationshipResult(
                    source_key=row["source_key"],
                    source_name=row["source_name"],
                    rel_type=row["rel_type"],
                    target_key=row["target_key"],
                    target_name=row["target_name"],
                    target_type=row["target_type"],
                    source=row["source"],
                )
                for row in result
            ]

    # ----- Graf gezintisi (analist senaryosu) -----

    def get_neighborhood(
        self, key: str, depth: int = 2, max_nodes: int = 100
    ) -> dict:
        """Verilen dugumun N derinlige kadar komsuluk altgrafini getir.

        Analist bir IOC/aktor sectiginde bu metotla cevresindeki tehdit
        ekosistemini gorsellestirir.
        """
        cypher = """
            MATCH path = (start:Entity {key: $key})-[r:RELATED*1..$depth]-(n:Entity)
            WITH nodes(path) AS ns, relationships(path) AS rs
            UNWIND ns AS node
            WITH DISTINCT node, rs
            RETURN node, rs
            LIMIT $max_nodes
        """
        # NOT: Neo4j variable-length path'te $depth degiskeni sinirli desteklidir.
        # Guvenli yol: depth'i Python tarafinda dogrula ve Cypher'e literal olarak koy.
        if depth < 1 or depth > 4:
            raise ValueError("depth 1 ile 4 arasinda olmali")

        cypher_safe = f"""
            MATCH path = (start:Entity {{key: $key}})-[:RELATED*1..{depth}]-(n:Entity)
            RETURN path
            LIMIT $max_nodes
        """
        with self._driver.session() as s:
            result = s.run(cypher_safe, key=key, max_nodes=max_nodes)
            nodes: dict[str, dict] = {}
            edges: list[dict] = []
            seen_edges: set[tuple] = set()
            for row in result:
                path = row["path"]
                for node in path.nodes:
                    nodes[node["key"]] = {
                        "key": node["key"],
                        "name": node.get("name"),
                        "type": node.get("type"),
                    }
                for rel in path.relationships:
                    src = rel.start_node["key"]
                    tgt = rel.end_node["key"]
                    edge_key = (src, tgt, rel["type"])
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({"source": src, "target": tgt, "type": rel["type"]})
        return {"nodes": list(nodes.values()), "edges": edges}

    # ----- Aktor profili (raporlama icin) -----

    def get_actor_profile(self, actor_key: str) -> dict:
        """Bir tehdit aktorunun kullandigi araclar, teknikler ve kampanyalar."""
        with self._driver.session() as s:
            actor = s.run(
                """
                MATCH (a:Entity {key: $key})
                RETURN a.key AS key, a.name AS name, a.description AS description
                """,
                key=actor_key,
            ).single()
            if actor is None:
                return {}

            uses = s.run(
                """
                MATCH (a:Entity {key: $key})-[r:RELATED {type: 'uses'}]->(t:Entity)
                RETURN t.key AS key, t.name AS name, t.type AS type
                ORDER BY t.type, t.name
                """,
                key=actor_key,
            )
            uses_list = [dict(row) for row in uses]

            attributed = s.run(
                """
                MATCH (c:Entity)-[:RELATED {type: 'attributed-to'}]->(a:Entity {key: $key})
                RETURN c.key AS key, c.name AS name, c.type AS type
                """,
                key=actor_key,
            )
            attributed_list = [dict(row) for row in attributed]

        by_type: dict[str, list] = {}
        for item in uses_list:
            by_type.setdefault(item["type"], []).append(item)

        return {
            "actor": dict(actor),
            "uses_by_type": by_type,
            "attributed_campaigns": attributed_list,
            "total_uses": len(uses_list),
        }
