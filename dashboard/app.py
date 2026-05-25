from __future__ import annotations

import streamlit as st

from cti_pipeline.analysis.prioritization import build_priority_findings
from cti_pipeline.llm.reporting import LLMDisabledError, build_llm_report
from cti_pipeline.reports.analyst_report import build_report
from cti_pipeline.settings import load_settings
from cti_pipeline.storage.sqlite_store import SQLiteStore


settings = load_settings()
store = SQLiteStore(settings.db_path)
store.init_db()


def dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_entity_graph(entity_type: str, value: str) -> str:
    linked_documents = store.entity_documents(entity_type, value, limit=8)
    co_entities = store.co_occurring_entities(entity_type, value, limit=12)
    selected_label = dot_escape(f"{entity_type}: {value}")
    lines = [
        "graph G {",
        "  graph [rankdir=LR, bgcolor=transparent];",
        '  node [shape=box, style="rounded,filled", color="#335c67", fillcolor="#f8f9fa", fontname="Arial"];',
        '  edge [color="#7a7a7a"];',
        f'  selected [label="{selected_label}", fillcolor="#d8f3dc", color="#2d6a4f"];',
    ]
    for index, row in enumerate(linked_documents):
        node_id = f"doc{index}"
        label = dot_escape(f"Document\\n{row['source_name']}\\n{row['title'][:60]}")
        lines.append(f'  {node_id} [label="{label}", fillcolor="#edf6f9"];')
        lines.append(f"  selected -- {node_id};")
    for index, row in enumerate(co_entities):
        node_id = f"entity{index}"
        label = dot_escape(f"{row['entity_type']}: {row['normalized_value']}\\n{row['shared_documents']} shared doc(s)")
        lines.append(f'  {node_id} [label="{label}", fillcolor="#fff3b0"];')
        lines.append(f"  selected -- {node_id};")
    lines.append("}")
    return "\n".join(lines)

st.set_page_config(page_title="CTI OSINT Dashboard", layout="wide")
st.title("LLM-Based Threat Intelligence Gathering")

days = st.sidebar.slider("Time window", min_value=1, max_value=3650, value=3650)

top_entities = store.top_entities(days=days, limit=50)
all_entities = store.all_entities(limit=200)
recent_documents = store.recent_documents(days=days, limit=50)
trend_signals = store.entity_trends(days=days, limit=100)
priority_findings = build_priority_findings(store, days=days, limit=25)

metric_cols = st.columns(3)
metric_cols[0].metric("Recent documents", len(recent_documents))
metric_cols[1].metric("Entity rows", len(top_entities))
metric_cols[2].metric("Window", f"{days} days")

tab_feed, tab_priorities, tab_entities, tab_trends, tab_explorer, tab_report = st.tabs(
    ["Threat Feed", "Priorities", "Entities", "Trends", "Entity Explorer", "Report"]
)

with tab_feed:
    st.subheader("Recent Documents")
    if recent_documents:
        st.dataframe(
            [
                {
                    "published_at": row["published_at"],
                    "source": row["source_name"],
                    "title": row["title"],
                    "url": row["url"],
                }
                for row in recent_documents
            ],
            use_container_width=True,
        )
    else:
        st.info("No documents yet. Run `python -m cti_pipeline.cli collect --source all`.")

with tab_priorities:
    st.subheader("Explainable Priority Queue")
    if priority_findings:
        st.dataframe(
            [
                {
                    "priority": finding.priority,
                    "score": finding.score,
                    "type": finding.entity_type,
                    "value": finding.value,
                    "confirmation": finding.confirmation,
                    "mentions": finding.mentions,
                    "sources": finding.source_count,
                    "last_seen": finding.last_seen,
                }
                for finding in priority_findings
            ],
            use_container_width=True,
        )
        for finding in priority_findings[:10]:
            with st.expander(f"{finding.priority.upper()} {finding.score} - {finding.entity_type} {finding.value}"):
                st.write("Rationale")
                for reason in finding.rationale:
                    st.write(f"- {reason}")
                st.write("Recommended actions")
                for action in finding.recommended_actions:
                    st.write(f"- {action}")
                st.write("Evidence")
                for document in finding.evidence_documents:
                    st.write(f"- Document {document['id']}: {document['source_name']} - {document['title']}")
                    st.link_button(f"Open document {document['id']}", document["url"])
    else:
        st.info("No priority findings yet. Run the pipeline first.")

with tab_entities:
    st.subheader("Top Extracted Entities")
    if top_entities:
        st.dataframe(
            [
                {
                    "type": row["entity_type"],
                    "value": row["normalized_value"],
                    "mentions": row["mentions"],
                }
                for row in top_entities
            ],
            use_container_width=True,
        )
    else:
        st.info("No extracted entities yet. Run `python -m cti_pipeline.cli extract`.")

with tab_trends:
    st.subheader("Trend Signals")
    if trend_signals:
        st.dataframe(
            [
                {
                    "type": trend["type"],
                    "value": trend["value"],
                    "mentions": trend["mentions"],
                    "sources": trend["source_count"],
                    "social": trend["social_mentions"],
                    "non_social": trend["non_social_mentions"],
                    "confirmation": trend["confirmation"],
                    "first_seen": trend["first_seen"],
                    "last_seen": trend["last_seen"],
                }
                for trend in trend_signals
            ],
            use_container_width=True,
        )
        selected_trend = st.selectbox(
            "Timeline entity",
            [f"{trend['type']} | {trend['value']}" for trend in trend_signals],
        )
        trend_type, trend_value = selected_trend.split(" | ", 1)
        timeline = store.entity_timeline(trend_type, trend_value, days=days)
        if timeline:
            st.line_chart(timeline, x="day", y=["mentions", "source_count"])
        else:
            st.info("No timeline data for this entity in the selected window.")
    else:
        st.info("No trend data yet. Run collection and extraction first.")

with tab_explorer:
    st.subheader("Entity Explorer")
    if all_entities:
        labels = [
            f"{row['entity_type']} | {row['normalized_value']} | {row['mentions']} mention(s)"
            for row in all_entities
        ]
        selected = st.selectbox("Select entity", labels)
        entity_type, value, _mentions = selected.split(" | ", 2)
        linked_documents = store.entity_documents(entity_type, value, limit=25)
        enrichments = store.entity_enrichments(entity_type, value)
        st.graphviz_chart(build_entity_graph(entity_type, value), use_container_width=True)
        if enrichments:
            st.subheader("Enrichment")
            for enrichment in enrichments:
                with st.expander(f"{enrichment['provider']} enrichment", expanded=True):
                    st.json(enrichment["payload"])
        st.caption(f"Source documents mentioning `{entity_type}` `{value}`")
        if linked_documents:
            for row in linked_documents:
                with st.expander(row["title"]):
                    st.write(row["body"])
                    st.write(f"Source: {row['source_name']}")
                    st.write(f"Published: {row['published_at'] or row['collected_at']}")
                    st.link_button("Open source", row["url"])
        else:
            st.info("No linked documents found for this entity.")
    else:
        st.info("No entities yet. Run collection and extraction first.")

with tab_report:
    st.subheader("Analyst Report")
    st.markdown(build_report(store, days=days))
    st.divider()
    st.subheader("LLM Analyst Report")
    if st.button("Generate LLM report"):
        try:
            st.markdown(build_llm_report(store, settings, days=days))
        except LLMDisabledError as exc:
            st.info(str(exc))
        except Exception as exc:
            st.error(f"LLM report generation failed: {exc}")
