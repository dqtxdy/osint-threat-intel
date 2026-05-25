from __future__ import annotations

import json

from neo4j import GraphDatabase

from cti_pipeline.settings import Settings
from cti_pipeline.storage.sqlite_store import SQLiteStore


ENTITY_LABELS = {
    "cve": "CVE",
    "attack_technique": "Technique",
    "domain": "Domain",
    "ip": "IPAddress",
    "url": "URL",
    "md5": "Hash",
    "sha1": "Hash",
    "sha256": "Hash",
    "product": "Product",
    "vendor": "Vendor",
    "ransomware_use": "RansomwareUse",
    "kev_catalog": "KEVEntry",
}


class Neo4jStore:
    def __init__(self, settings: Settings):
        self.driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    def close(self) -> None:
        self.driver.close()

    def create_constraints(self) -> None:
        statements = [
            "CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT entity_key IF NOT EXISTS FOR (e:Entity) REQUIRE (e.type, e.value) IS UNIQUE",
            "CREATE CONSTRAINT source_id IF NOT EXISTS FOR (s:Source) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT report_id IF NOT EXISTS FOR (r:Report) REQUIRE r.id IS UNIQUE",
        ]
        with self.driver.session() as session:
            for statement in statements:
                session.run(statement)

    def sync_from_sqlite(self, store: SQLiteStore) -> None:
        self.create_constraints()
        with store.connect() as connection, self.driver.session() as session:
            documents = list(connection.execute("SELECT * FROM documents"))
            for row in documents:
                session.run(
                    """
                    MERGE (s:Source {id: $source_id})
                    SET s.name = $source_name, s.type = $source_type
                    MERGE (d:Document {id: $document_id})
                    SET d.title = $title, d.url = $url, d.published_at = $published_at
                    MERGE (s)-[:PUBLISHED]->(d)
                    """,
                    source_id=row["source_id"],
                    source_name=row["source_name"],
                    source_type=row["source_type"],
                    document_id=row["id"],
                    title=row["title"],
                    url=row["url"],
                    published_at=row["published_at"],
                )

            edges = list(
                connection.execute(
                    """
                    SELECT d.id AS document_id, e.entity_type, e.normalized_value, de.confidence, de.evidence
                    FROM document_entities de
                    JOIN documents d ON d.id = de.document_id
                    JOIN entities e ON e.id = de.entity_id
                    """
                )
            )
            for row in edges:
                enrichment_rows = list(
                    connection.execute(
                        """
                        SELECT ee.provider, ee.payload, ee.enriched_at
                        FROM entity_enrichments ee
                        JOIN entities e ON e.id = ee.entity_id
                        WHERE e.entity_type = ? AND e.normalized_value = ?
                        ORDER BY ee.provider
                        """,
                        (row["entity_type"], row["normalized_value"]),
                    )
                )
                enrichment_json = json.dumps(
                    [
                        {
                            "provider": enrichment["provider"],
                            "payload": json.loads(enrichment["payload"]),
                            "enriched_at": enrichment["enriched_at"],
                        }
                        for enrichment in enrichment_rows
                    ],
                    ensure_ascii=False,
                )
                session.run(
                    """
                    MATCH (d:Document {id: $document_id})
                    MERGE (e:Entity {type: $entity_type, value: $value})
                    SET e.enrichment_json = $enrichment_json
                    MERGE (d)-[r:MENTIONS]->(e)
                    SET r.confidence = $confidence, r.evidence = $evidence
                    """,
                    document_id=row["document_id"],
                    entity_type=row["entity_type"],
                    value=row["normalized_value"],
                    enrichment_json=enrichment_json,
                    confidence=row["confidence"],
                    evidence=row["evidence"],
                )
                label = ENTITY_LABELS.get(row["entity_type"])
                if label:
                    session.run(
                        f"""
                        MATCH (e:Entity {{type: $entity_type, value: $value}})
                        SET e:{label}
                        """,
                        entity_type=row["entity_type"],
                        value=row["normalized_value"],
                    )

            self._sync_cve_product_relationships(connection, session)
            self._sync_cve_kev_relationships(connection, session)

    def _sync_cve_product_relationships(self, connection, session) -> None:
        rows = list(
            connection.execute(
                """
                SELECT d.id AS document_id, cve.normalized_value AS cve, product.normalized_value AS product
                FROM document_entities de_cve
                JOIN entities cve ON cve.id = de_cve.entity_id AND cve.entity_type = 'cve'
                JOIN document_entities de_product ON de_product.document_id = de_cve.document_id
                JOIN entities product ON product.id = de_product.entity_id AND product.entity_type = 'product'
                JOIN documents d ON d.id = de_cve.document_id
                """
            )
        )
        for row in rows:
            session.run(
                """
                MERGE (cve:Entity:CVE {type: 'cve', value: $cve})
                MERGE (product:Entity:Product {type: 'product', value: $product})
                MERGE (cve)-[r:AFFECTS]->(product)
                SET r.evidence_document_id = $document_id
                """,
                cve=row["cve"],
                product=row["product"],
                document_id=row["document_id"],
            )

    def _sync_cve_kev_relationships(self, connection, session) -> None:
        rows = list(
            connection.execute(
                """
                SELECT d.id AS document_id, cve.normalized_value AS cve, kev.normalized_value AS kev
                FROM document_entities de_cve
                JOIN entities cve ON cve.id = de_cve.entity_id AND cve.entity_type = 'cve'
                JOIN document_entities de_kev ON de_kev.document_id = de_cve.document_id
                JOIN entities kev ON kev.id = de_kev.entity_id AND kev.entity_type = 'kev_catalog'
                JOIN documents d ON d.id = de_cve.document_id
                WHERE cve.normalized_value = kev.normalized_value
                """
            )
        )
        for row in rows:
            session.run(
                """
                MERGE (cve:Entity:CVE {type: 'cve', value: $cve})
                MERGE (kev:Entity:KEVEntry {type: 'kev_catalog', value: $kev})
                MERGE (cve)-[r:LISTED_IN]->(kev)
                SET r.catalog = 'CISA KEV', r.evidence_document_id = $document_id
                """,
                cve=row["cve"],
                kev=row["kev"],
                document_id=row["document_id"],
            )
