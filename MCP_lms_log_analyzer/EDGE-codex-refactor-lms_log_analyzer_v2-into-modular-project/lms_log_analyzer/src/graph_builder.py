"""Neo4j 互動模組

This stub demonstrates how analysis results could be stored in a graph
database. Functions are minimal to keep dependencies optional.
"""

from typing import Iterable, Mapping

try:
    from neo4j import GraphDatabase
except Exception:  # pragma: no cover - optional
    GraphDatabase = None  # type: ignore

from .. import config


class GraphBuilder:
    """Create entities and relations in Neo4j if the driver is available."""

    def __init__(self) -> None:
        if GraphDatabase is None:
            self._driver = None
        else:
            self._driver = GraphDatabase.driver(
                config.NEO4J_URI,
                auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
            )

    def create_entities(self, entities: Iterable[Mapping[str, object]]) -> None:
        if not self._driver:
            return
        with self._driver.session() as session:
            for ent in entities:
                session.run(
                    "MERGE (n:%s {id: $id}) SET n += $props"
                    % ent.get("label", "Entity"),
                    id=ent.get("id"),
                    props=ent.get("properties", {}),
                )

    def create_relations(self, relations: Iterable[Mapping[str, object]]) -> None:
        if not self._driver:
            return
        with self._driver.session() as session:
            for rel in relations:
                session.run(
                    "MATCH (a {id: $start}), (b {id: $end}) "
                    "MERGE (a)-[:%s]->(b)" % rel.get("type", "RELATED"),
                    start=rel.get("start_id"),
                    end=rel.get("end_id"),
                )
