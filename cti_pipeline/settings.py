from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path
    sources_path: Path
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    llm_provider: str
    llm_model: str
    llm_base_url: str
    llm_api_key: str | None


def load_settings() -> Settings:
    return Settings(
        db_path=Path(os.getenv("CTI_DB_PATH", "data/cti.sqlite3")),
        sources_path=Path(os.getenv("CTI_SOURCES_PATH", "config/sources.yml")),
        neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
        neo4j_password=os.getenv("NEO4J_PASSWORD", "capstonepassword"),
        llm_provider=os.getenv("LLM_PROVIDER", "disabled"),
        llm_model=os.getenv("LLM_MODEL", "gemini-2.5-flash"),
        llm_base_url=os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
        llm_api_key=os.getenv("LLM_API_KEY"),
    )
