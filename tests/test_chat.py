from __future__ import annotations

import pytest
from fastapi import HTTPException

from cti_pipeline.models import Document, Entity
from cti_pipeline.storage.sqlite_store import SQLiteStore
from cti_pipeline.chat.retrieval import build_chat_context
from cti_pipeline.llm.reporting import LLMDisabledError
from cti_pipeline.llm.chat import build_chat_response, ChatResponse
from cti_pipeline.api.main import ChatMessage, ChatRequest, api_chat


def test_retrieval_returns_relevant_context(tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    store = SQLiteStore(db_path)
    store.init_db()

    # Insert test document
    store.insert_documents(
        [
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/cve",
                title="CVE-2024-3400 Exploited",
                body="Palo Alto GlobalProtect VPN vulnerability active in the wild.",
                language="en",
            )
        ]
    )
    with store.connect() as connection:
        doc_id = connection.execute("SELECT id FROM documents").fetchone()["id"]
    store.insert_document_entities(
        doc_id,
        [Entity("cve", "CVE-2024-3400", "CVE-2024-3400")],
        evidence="CVE-2024-3400 Exploited",
    )

    # Run retrieval
    context = build_chat_context(store, "What do we know about CVE-2024-3400?", days=3650, limit=5)

    # Verify elements are populated
    assert context["counts"]["documents"] == 1
    assert len(context["documents"]) == 1
    assert context["documents"][0]["id"] == doc_id
    assert context["documents"][0]["title"] == "CVE-2024-3400 Exploited"
    assert len(context["matching_entities"]) > 0
    assert context["matching_entities"][0]["value"] == "CVE-2024-3400"


def test_retrieval_expands_phishing_intent(tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    store = SQLiteStore(db_path)
    store.init_db()
    store.insert_documents(
        [
            Document(
                source_id="phishtank",
                source_name="PhishTank Verified Active Phishing",
                source_type="threat_feed",
                url="https://phishtank.org/phish_detail.php?phish_id=1",
                title="PhishTank 1 - Example Brand",
                body="Verified active phishing URL targeting Example Brand credentials.",
                language="en",
            ),
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/cve",
                title="CVE-2024-3400 Exploited",
                body="Palo Alto GlobalProtect VPN vulnerability active in the wild.",
                language="en",
            ),
        ]
    )

    context = build_chat_context(store, "Summarize phishing activity.", days=3650, limit=3)

    assert context["documents"]
    assert context["documents"][0]["source_id"] == "phishtank"
    assert "phishing" in context["documents"][0]["body_excerpt"].lower()


def test_chat_response_with_citations_and_disabled(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    store = SQLiteStore(db_path)
    store.init_db()
    store.insert_documents(
        [
            Document(
                source_id="cisa_kev",
                source_name="CISA KEV",
                source_type="structured_feed",
                url="https://example.test/cve",
                title="CVE-2024-3400 Exploited",
                body="Palo Alto GlobalProtect VPN vulnerability active in the wild.",
                language="en",
            )
        ]
    )

    from cti_pipeline.settings import Settings

    # 1. Disabled settings behavior
    settings_disabled = Settings(
        db_path=db_path,
        sources_path=tmp_path / "sources.yml",
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="password",
        llm_provider="disabled",
        llm_model="gemini-2.5-flash",
        llm_base_url="http://fake",
        llm_api_key=None,
    )

    with pytest.raises(LLMDisabledError):
        build_chat_response(store, settings_disabled, [{"role": "user", "content": "hello"}])

    # 2. Enabled settings but mock HTTP responses to simulate LLM call
    settings_enabled = Settings(
        db_path=db_path,
        sources_path=tmp_path / "sources.yml",
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="password",
        llm_provider="openai_compatible",
        llm_model="gemini-2.5-flash",
        llm_base_url="http://fake",
        llm_api_key="fake-key",
    )

    # Mock httpx.post response
    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"answer": "CVE-2024-3400 is active.", "citations": [{"document_id": 1, "title": "CVE-2024-3400 Exploited", "source_name": "CISA KEV", "url": "https://example.test/cve"}, {"document_id": 999, "title": "Fake", "source_name": "Fake", "url": "https://fake.test"}], "related_entities": [{"type": "cve", "value": "CVE-2024-3400"}], "suggested_followups": ["What products are affected?"], "caveats": ["Only one document covers this threat."]}'
                        }
                    }
                ]
            }

    def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.post", mock_post)

    response = build_chat_response(store, settings_enabled, [{"role": "user", "content": "What do you know?"}])
    assert isinstance(response, ChatResponse)
    assert response.answer == "CVE-2024-3400 is active."
    assert len(response.citations) == 1
    assert response.citations[0].document_id == 1
    assert response.citations[0].title == "CVE-2024-3400 Exploited"


def test_api_chat_endpoint_works(monkeypatch, tmp_path):
    db_path = tmp_path / "cti.sqlite3"
    monkeypatch.setenv("CTI_DB_PATH", str(db_path))

    # 1. Test endpoint when LLM is disabled (no environment keys set)
    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    request = ChatRequest(messages=[ChatMessage(role="user", content="test query")], days=3650)
    with pytest.raises(HTTPException) as exc:
        api_chat(request)
    assert exc.value.status_code == 400
    assert "Set LLM_PROVIDER=openai_compatible" in exc.value.detail

    # 2. Test endpoint when LLM is enabled (with monkeypatched httpx.post)
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("LLM_API_KEY", "dummy-api-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"answer": "Analyzed successfully.", "citations": [], "related_entities": [], "suggested_followups": [], "caveats": []}'
                        }
                    }
                ]
            }

    def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.post", mock_post)

    response = api_chat(ChatRequest(messages=[ChatMessage(role="user", content="hello")], days=3650))
    data = response.model_dump()
    assert data["answer"] == "Analyzed successfully."
    assert data["citations"] == []
