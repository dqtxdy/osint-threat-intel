from __future__ import annotations

import json
from typing import Any
import httpx
from pydantic import BaseModel, Field, ValidationError

from cti_pipeline.settings import Settings
from cti_pipeline.storage.sqlite_store import SQLiteStore
from cti_pipeline.llm.reporting import LLMDisabledError
from cti_pipeline.chat.retrieval import build_chat_context


class ChatCitation(BaseModel):
    document_id: int
    title: str
    source_name: str
    url: str


class ChatRelatedEntity(BaseModel):
    type: str
    value: str


class ChatResponse(BaseModel):
    answer: str
    citations: list[ChatCitation] = Field(default_factory=list)
    related_entities: list[ChatRelatedEntity] = Field(default_factory=list)
    suggested_followups: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


def build_chat_response(
    store: SQLiteStore,
    settings: Settings,
    messages: list[dict[str, str]],
    days: int = 3650,
) -> ChatResponse:
    if settings.llm_provider != "openai_compatible" or not settings.llm_api_key:
        raise LLMDisabledError("Set LLM_PROVIDER=openai_compatible and LLM_API_KEY to enable LLM chat.")

    safe_messages = _safe_conversation(messages)

    # Get latest user message to search database
    last_user_message = ""
    for msg in reversed(safe_messages):
        if msg.get("role") == "user":
            last_user_message = msg.get("content", "")
            break
    if not last_user_message:
        raise ValueError("Chat requires at least one user message.")

    # Build context from SQLite database
    context = build_chat_context(store, last_user_message, days=days)

    # Call LLM
    response = httpx.post(
        settings.llm_base_url,
        headers={
            "Authorization": f"Bearer {settings.llm_api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.llm_model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _system_prompt(context)},
                *safe_messages,
            ],
        },
        timeout=60,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    
    # Sanitize response
    cleaned_content = content.strip()
    if cleaned_content.startswith("```json"):
        cleaned_content = cleaned_content.removeprefix("```json").strip()
    elif cleaned_content.startswith("```"):
        cleaned_content = cleaned_content.removeprefix("```").strip()
    if cleaned_content.endswith("```"):
        cleaned_content = cleaned_content.removesuffix("```").strip()
    
    start_idx = cleaned_content.find("{")
    end_idx = cleaned_content.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        cleaned_content = cleaned_content[start_idx:end_idx + 1]

    try:
        chat_response = ChatResponse.model_validate_json(cleaned_content)
        return _trustworthy_response(chat_response, context)
    except ValidationError as exc:
        raise ValueError(f"LLM returned invalid chat JSON: {exc}") from exc


def _safe_conversation(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    safe_messages = []
    for message in messages[-12:]:
        role = message.get("role")
        content = str(message.get("content", "")).strip()
        if role not in {"user", "assistant"} or not content:
            continue
        safe_messages.append({"role": role, "content": content[:4000]})
    return safe_messages


def _trustworthy_response(response: ChatResponse, context: dict[str, Any]) -> ChatResponse:
    citations_by_id = _context_citations(context)
    citations: list[ChatCitation] = []
    seen: set[int] = set()
    for citation in response.citations:
        trusted = citations_by_id.get(citation.document_id)
        if not trusted or citation.document_id in seen:
            continue
        seen.add(citation.document_id)
        citations.append(trusted)

    return ChatResponse(
        answer=response.answer,
        citations=citations,
        related_entities=response.related_entities[:12],
        suggested_followups=response.suggested_followups[:5],
        caveats=response.caveats[:6],
    )


def _context_citations(context: dict[str, Any]) -> dict[int, ChatCitation]:
    citations: dict[int, ChatCitation] = {}
    for document in context.get("documents", []):
        citations[int(document["id"])] = ChatCitation(
            document_id=int(document["id"]),
            title=str(document["title"]),
            source_name=str(document["source_name"]),
            url=str(document["url"]),
        )

    for priority in context.get("top_priorities", []):
        for document in priority.get("evidence_documents", []):
            document_id = int(document["id"])
            citations.setdefault(
                document_id,
                ChatCitation(
                    document_id=document_id,
                    title=str(document["title"]),
                    source_name=str(document["source_name"]),
                    url=str(document["url"]),
                ),
            )
    return citations


def _system_prompt(context: dict[str, Any]) -> str:
    compact_context = _compact_chat_context(context)
    context_str = json.dumps(compact_context, ensure_ascii=False)
    return f"""
You are a defensive cyber threat intelligence analyst assistant.
You must answer the user's questions based ONLY on the provided security evidence and intelligence context.

INTELLIGENCE CONTEXT:
{context_str}

CRITICAL RULES:
1. Answer only from the provided intelligence context. Do NOT assume or extrapolate beyond the provided data.
2. If the retrieved evidence/context is weak, missing, or insufficient to answer the question, explicitly state that in your answer and caveats.
3. Cite evidence using document IDs and source names in the text of your answer (e.g., "[Document 123 (CISA KEV)]").
4. Never include offensive exploit steps or step-by-step guidance for executing attacks. Focus on defense, remediation, and awareness.
5. Explain source limitations if relevant (e.g., if data only comes from social sources and lacks structured validation).
6. Write in a professional, concise, analyst-style tone.
7. Return a valid JSON response adhering exactly to this JSON schema:
{{
  "answer": "analyst answer text",
  "citations": [
    {{
      "document_id": 123,
      "title": "Document Title",
      "source_name": "Source Name",
      "url": "https://example.com"
    }}
  ],
  "related_entities": [
    {{
      "type": "cve|ip|domain|attack_technique|...",
      "value": "entity value"
    }}
  ],
  "suggested_followups": ["follow-up question 1", "follow-up question 2"],
  "caveats": ["caveat or limitation 1"]
}}
""".strip()


def _compact_chat_context(context: dict[str, Any]) -> dict[str, Any]:
    documents = []
    for doc in context.get("documents", []):
        documents.append({
            "id": doc["id"],
            "source_name": doc["source_name"],
            "source_type": doc["source_type"],
            "title": doc["title"],
            "published_at": str(doc["published_at"]),
            "url": doc["url"],
            "body_excerpt": doc["body_excerpt"][:1200],
            "entities": doc.get("entities", []),
        })
    return {
        "counts": context.get("counts", {}),
        "gaps": context.get("gaps", []),
        "source_mix": context.get("source_mix", []),
        "top_priorities": context.get("top_priorities", [])[:6],
        "documents": documents,
        "matching_entities": context.get("matching_entities", [])[:15],
        "trends": context.get("trends", [])[:15],
    }
