from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cti_pipeline.cleaning import content_hash
from cti_pipeline.models import Document, Entity


class SQLiteStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def init_db(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    language TEXT,
                    published_at TEXT,
                    collected_at TEXT NOT NULL,
                    extracted_at TEXT,
                    content_hash TEXT NOT NULL UNIQUE,
                    raw_metadata TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    UNIQUE(entity_type, normalized_value)
                );

                CREATE TABLE IF NOT EXISTS document_entities (
                    document_id INTEGER NOT NULL,
                    entity_id INTEGER NOT NULL,
                    relationship TEXT NOT NULL DEFAULT 'MENTIONS',
                    confidence REAL NOT NULL DEFAULT 1.0,
                    evidence TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY(document_id, entity_id, relationship),
                    FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
                    FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS entity_enrichments (
                    entity_id INTEGER NOT NULL,
                    provider TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    enriched_at TEXT NOT NULL,
                    PRIMARY KEY(entity_id, provider),
                    FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );
                """
            )
            self._ensure_column(connection, "documents", "extracted_at", "TEXT")

    def backup(self, output_dir: Path | None = None) -> Path | None:
        if not self.path.exists():
            return None
        backup_dir = output_dir or self.path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_dir / f"{self.path.stem}_{timestamp}{self.path.suffix}"
        shutil.copy2(self.path, backup_path)
        return backup_path

    def clear_all(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                DELETE FROM entity_enrichments;
                DELETE FROM document_entities;
                DELETE FROM entities;
                DELETE FROM documents;
                DELETE FROM sqlite_sequence
                WHERE name IN ('documents', 'entities');
                """
            )

    def insert_documents(self, documents: list[Document]) -> tuple[int, int]:
        inserted = 0
        duplicates = 0
        with self.connect() as connection:
            for document in documents:
                digest = content_hash(document.title, document.body)
                try:
                    connection.execute(
                        """
                        INSERT INTO documents (
                            source_id, source_name, source_type, url, title, body,
                            language, published_at, collected_at, content_hash, raw_metadata
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            document.source_id,
                            document.source_name,
                            document.source_type,
                            document.url,
                            document.title,
                            document.body,
                            document.language,
                            _dt(document.published_at),
                            _dt(document.collected_at),
                            digest,
                            json.dumps(document.raw_metadata, ensure_ascii=False),
                        ),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    duplicates += 1
        return inserted, duplicates

    def fetch_documents_pending_extraction(self, limit: int | None = None) -> list[sqlite3.Row]:
        sql = """
            SELECT d.*
            FROM documents d
            WHERE d.extracted_at IS NULL
            ORDER BY COALESCE(d.published_at, d.collected_at) DESC
        """
        params: tuple[int, ...] = ()
        if limit:
            sql += " LIMIT ?"
            params = (limit,)
        with self.connect() as connection:
            return list(connection.execute(sql, params))

    def insert_document_entities(self, document_id: int, entities: list[Entity], evidence: str) -> int:
        inserted = 0
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            for entity in entities:
                cursor = connection.execute(
                    """
                    INSERT INTO entities (entity_type, value, normalized_value, confidence)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(entity_type, normalized_value) DO UPDATE SET
                        value = excluded.value,
                        confidence = MAX(entities.confidence, excluded.confidence)
                    RETURNING id
                    """,
                    (entity.entity_type, entity.value, entity.normalized_value, entity.confidence),
                )
                entity_id = int(cursor.fetchone()["id"])
                connection.execute(
                    """
                    INSERT INTO document_entities (
                        document_id, entity_id, relationship, confidence, evidence, first_seen, last_seen
                    )
                    VALUES (?, ?, 'MENTIONS', ?, ?, ?, ?)
                    ON CONFLICT(document_id, entity_id, relationship) DO UPDATE SET
                        last_seen = excluded.last_seen
                    """,
                    (document_id, entity_id, entity.confidence, evidence[:500], now, now),
                )
                inserted += 1
        return inserted

    def mark_document_extracted(self, document_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                "UPDATE documents SET extracted_at = ? WHERE id = ?",
                (now, document_id),
            )

    def top_entities(self, days: int = 7, limit: int = 25) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT e.entity_type, e.normalized_value, COUNT(*) AS mentions
                    FROM entities e
                    JOIN document_entities de ON de.entity_id = e.id
                    JOIN documents d ON d.id = de.document_id
                    WHERE datetime(COALESCE(d.published_at, d.collected_at)) >= datetime('now', ?)
                    GROUP BY e.entity_type, e.normalized_value
                    ORDER BY mentions DESC, e.entity_type, e.normalized_value
                    LIMIT ?
                    """,
                    (f"-{days} days", limit),
                )
            )

    def recent_documents(self, days: int = 7, limit: int = 50) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT *
                    FROM documents
                    WHERE datetime(COALESCE(published_at, collected_at)) >= datetime('now', ?)
                    ORDER BY COALESCE(published_at, collected_at) DESC
                    LIMIT ?
                    """,
                    (f"-{days} days", limit),
                )
            )

    def entity_count(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM entities").fetchone()
            return int(row["count"])

    def entity_documents(self, entity_type: str, normalized_value: str, limit: int = 20) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT d.*
                    FROM documents d
                    JOIN document_entities de ON de.document_id = d.id
                    JOIN entities e ON e.id = de.entity_id
                    WHERE e.entity_type = ? AND e.normalized_value = ?
                    ORDER BY COALESCE(d.published_at, d.collected_at) DESC
                    LIMIT ?
                    """,
                    (entity_type, normalized_value, limit),
                )
            )

    def co_occurring_entities(self, entity_type: str, normalized_value: str, limit: int = 25) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    WITH selected_documents AS (
                        SELECT de.document_id
                        FROM document_entities de
                        JOIN entities e ON e.id = de.entity_id
                        WHERE e.entity_type = ? AND e.normalized_value = ?
                    )
                    SELECT other.entity_type, other.normalized_value, COUNT(*) AS shared_documents
                    FROM selected_documents sd
                    JOIN document_entities de2 ON de2.document_id = sd.document_id
                    JOIN entities other ON other.id = de2.entity_id
                    WHERE NOT (other.entity_type = ? AND other.normalized_value = ?)
                    GROUP BY other.entity_type, other.normalized_value
                    ORDER BY shared_documents DESC, other.entity_type, other.normalized_value
                    LIMIT ?
                    """,
                    (entity_type, normalized_value, entity_type, normalized_value, limit),
                )
            )

    def all_entities(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT e.entity_type, e.normalized_value, COUNT(de.document_id) AS mentions
                    FROM entities e
                    LEFT JOIN document_entities de ON de.entity_id = e.id
                    GROUP BY e.entity_type, e.normalized_value
                    ORDER BY mentions DESC, e.entity_type, e.normalized_value
                    LIMIT ?
                    """,
                    (limit,),
                )
            )

    def entities_by_type(self, entity_type: str) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT id, entity_type, normalized_value
                    FROM entities
                    WHERE entity_type = ?
                    ORDER BY normalized_value
                    """,
                    (entity_type,),
                )
            )

    def upsert_entity_enrichment(self, entity_id: int, provider: str, payload: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO entity_enrichments (entity_id, provider, payload, enriched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(entity_id, provider) DO UPDATE SET
                    payload = excluded.payload,
                    enriched_at = excluded.enriched_at
                """,
                (entity_id, provider, json.dumps(payload, ensure_ascii=False), now),
            )

    def entity_enrichments(self, entity_type: str, normalized_value: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = list(
                connection.execute(
                    """
                    SELECT ee.provider, ee.payload, ee.enriched_at
                    FROM entity_enrichments ee
                    JOIN entities e ON e.id = ee.entity_id
                    WHERE e.entity_type = ? AND e.normalized_value = ?
                    ORDER BY ee.provider
                    """,
                    (entity_type, normalized_value),
                )
            )
        return [
            {
                "provider": row["provider"],
                "payload": json.loads(row["payload"]),
                "enriched_at": row["enriched_at"],
            }
            for row in rows
        ]

    def enriched_entity_summary(self, days: int = 7, limit: int = 25) -> list[dict[str, Any]]:
        rows = self.top_entities(days=days, limit=limit)
        summary: list[dict[str, Any]] = []
        for row in rows:
            summary.append(
                {
                    "type": row["entity_type"],
                    "value": row["normalized_value"],
                    "mentions": row["mentions"],
                    "enrichments": self.entity_enrichments(row["entity_type"], row["normalized_value"]),
                }
            )
        return summary

    def entity_trends(self, days: int = 7, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = list(
                connection.execute(
                    """
                    SELECT
                        e.entity_type,
                        e.normalized_value,
                        COUNT(*) AS mentions,
                        COUNT(DISTINCT d.source_id) AS source_count,
                        SUM(CASE WHEN d.source_type = 'social' THEN 1 ELSE 0 END) AS social_mentions,
                        SUM(CASE WHEN d.source_type != 'social' THEN 1 ELSE 0 END) AS non_social_mentions,
                        MIN(COALESCE(d.published_at, d.collected_at)) AS first_seen,
                        MAX(COALESCE(d.published_at, d.collected_at)) AS last_seen
                    FROM entities e
                    JOIN document_entities de ON de.entity_id = e.id
                    JOIN documents d ON d.id = de.document_id
                    WHERE datetime(COALESCE(d.published_at, d.collected_at)) >= datetime('now', ?)
                    GROUP BY e.entity_type, e.normalized_value
                    ORDER BY source_count DESC, mentions DESC, e.entity_type, e.normalized_value
                    LIMIT ?
                    """,
                    (f"-{days} days", limit),
                )
            )
        return [
            {
                "type": row["entity_type"],
                "value": row["normalized_value"],
                "mentions": row["mentions"],
                "source_count": row["source_count"],
                "social_mentions": row["social_mentions"],
                "non_social_mentions": row["non_social_mentions"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "confirmation": _confirmation_label(row["social_mentions"], row["non_social_mentions"]),
                "enrichments": self.entity_enrichments(row["entity_type"], row["normalized_value"]),
            }
            for row in rows
        ]

    def entity_timeline(self, entity_type: str, normalized_value: str, days: int = 30) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = list(
                connection.execute(
                    """
                    SELECT
                        date(COALESCE(d.published_at, d.collected_at)) AS day,
                        COUNT(*) AS mentions,
                        COUNT(DISTINCT d.source_id) AS source_count
                    FROM documents d
                    JOIN document_entities de ON de.document_id = d.id
                    JOIN entities e ON e.id = de.entity_id
                    WHERE e.entity_type = ?
                      AND e.normalized_value = ?
                      AND datetime(COALESCE(d.published_at, d.collected_at)) >= datetime('now', ?)
                    GROUP BY day
                    ORDER BY day
                    """,
                    (entity_type, normalized_value, f"-{days} days"),
                )
            )
        return [
            {
                "day": row["day"],
                "mentions": row["mentions"],
                "source_count": row["source_count"],
            }
            for row in rows
        ]

    def recent_documents_with_entities(self, days: int = 7, limit: int = 12) -> list[dict[str, Any]]:
        documents = self.recent_documents(days=days, limit=limit)
        with self.connect() as connection:
            results: list[dict[str, Any]] = []
            for document in documents:
                entity_rows = list(
                    connection.execute(
                        """
                        SELECT e.entity_type, e.normalized_value
                        FROM entities e
                        JOIN document_entities de ON de.entity_id = e.id
                        WHERE de.document_id = ?
                        ORDER BY e.entity_type, e.normalized_value
                        """,
                        (document["id"],),
                    )
                )
                results.append(
                    {
                        "id": document["id"],
                        "source_name": document["source_name"],
                        "source_type": document["source_type"],
                        "title": document["title"],
                        "body": document["body"],
                        "url": document["url"],
                        "published_at": document["published_at"] or document["collected_at"],
                        "entities": [
                            {"type": row["entity_type"], "value": row["normalized_value"]}
                            for row in entity_rows
                        ],
                    }
                )
            return results

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _confirmation_label(social_mentions: int, non_social_mentions: int) -> str:
    if social_mentions and non_social_mentions:
        return "social + corroborated"
    if non_social_mentions:
        return "official/structured only"
    return "social only"
