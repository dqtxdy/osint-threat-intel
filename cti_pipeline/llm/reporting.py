from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from cti_pipeline.settings import Settings
from cti_pipeline.storage.sqlite_store import SQLiteStore


class LLMDisabledError(RuntimeError):
    pass


class ReportFinding(BaseModel):
    title: str
    summary: str
    confidence: str = Field(pattern="^(low|medium|high)$")
    evidence_document_ids: list[int]


class LLMAnalystReport(BaseModel):
    executive_summary: str
    key_findings: list[ReportFinding]
    priority_entities: list[str]
    recommended_actions: list[str]
    caveats: list[str]


def build_llm_report(store: SQLiteStore, settings: Settings, days: int = 7) -> str:
    if settings.llm_provider == "disabled" or not settings.llm_api_key:
        raise LLMDisabledError("Set LLM_PROVIDER=openai_compatible and LLM_API_KEY to enable LLM reports.")

    context = _build_context(store, days=days)
    report = _call_openai_compatible(settings, context)
    return render_llm_report(report, context, days=days)


def render_llm_report(report: LLMAnalystReport, context: dict[str, Any], days: int) -> str:
    source_map = {document["id"]: document for document in context["documents"]}
    lines = [
        f"# LLM Analyst Report - Last {days} Days",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Key Findings",
        "",
    ]

    if report.key_findings:
        for finding in report.key_findings:
            evidence = ", ".join(f"Document {doc_id}" for doc_id in finding.evidence_document_ids)
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    finding.summary,
                    "",
                    f"Confidence: `{finding.confidence}`",
                    "",
                    f"Evidence: {evidence or 'No evidence IDs supplied'}",
                    "",
                ]
            )
    else:
        lines.append("No key findings were generated.")

    lines.extend(["## Priority Entities", ""])
    lines.extend(f"- {entity}" for entity in report.priority_entities)
    if not report.priority_entities:
        lines.append("- None")

    lines.extend(["", "## Recommended Defensive Actions", ""])
    lines.extend(f"- {action}" for action in report.recommended_actions)
    if not report.recommended_actions:
        lines.append("- None")

    lines.extend(["", "## Caveats", ""])
    lines.extend(f"- {caveat}" for caveat in report.caveats)
    if not report.caveats:
        lines.append("- Claims are limited to the provided source documents.")

    lines.extend(["", "## Evidence Sources", ""])
    for document_id in sorted(source_map):
        document = source_map[document_id]
        lines.append(f"- Document {document_id}: {document['source_name']} | [{document['title']}]({document['url']})")

    return "\n".join(lines)


def _build_context(store: SQLiteStore, days: int) -> dict[str, Any]:
    return {
        "documents": store.recent_documents_with_entities(days=days, limit=12),
        "top_entities": store.enriched_entity_summary(days=days, limit=25),
        "trend_signals": store.entity_trends(days=days, limit=25),
    }


def _call_openai_compatible(settings: Settings, context: dict[str, Any]) -> LLMAnalystReport:
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
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": json.dumps(_compact_context(context), ensure_ascii=False)},
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
        return LLMAnalystReport.model_validate_json(cleaned_content)
    except ValidationError as exc:
        raise ValueError(f"LLM returned invalid report JSON: {exc}. Original content: {content}") from exc


def _system_prompt() -> str:
    return """
You are a defensive cyber threat intelligence analyst.
Use only the provided source documents and entity list.
Return valid JSON matching this schema:
{
  "executive_summary": "short paragraph",
  "key_findings": [
    {
      "title": "finding title",
      "summary": "evidence-backed finding",
      "confidence": "low|medium|high",
      "evidence_document_ids": [1, 2]
    }
  ],
  "priority_entities": ["CVE-... or entity name"],
  "recommended_actions": ["defensive action"],
  "caveats": ["uncertainty or source limitation"]
}
Do not invent facts. Do not include exploit instructions or offensive step-by-step guidance.
If social content is not corroborated by structured or official sources, say so in caveats.
""".strip()


def _compact_context(context: dict[str, Any]) -> dict[str, Any]:
    documents = []
    for document in context["documents"]:
        documents.append(
            {
                "id": document["id"],
                "source_name": document["source_name"],
                "source_type": document["source_type"],
                "title": document["title"],
                "published_at": document["published_at"],
                "url": document["url"],
                "body_excerpt": document["body"][:1200],
                "entities": document["entities"],
            }
        )
    return {"documents": documents, "top_entities": context["top_entities"]}
