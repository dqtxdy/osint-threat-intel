# Demo Script

## Pre-Demo Reset

Run:

```bash
python3 -m cti_pipeline.cli run-pipeline --source all --days 3650
python3 -m streamlit run dashboard/app.py
```

If Neo4j is part of the demo:

```bash
docker compose up -d neo4j
python3 -m cti_pipeline.cli sync-neo4j
```

## Presentation Flow

1. Open the dashboard.
2. Show **Threat Feed** to explain public OSINT collection.
3. Show **Priorities** to explain score, rationale, evidence, and recommended actions.
4. Show **Trends** and point out `social + corroborated` versus `social only`.
5. Show **Entity Explorer** for `CVE-2024-3400`.
6. Point out source evidence, co-mentioned entities, and enrichment data.
7. Show **Report** and explain that claims are evidence-backed.
8. If an LLM key is configured, click **Generate LLM report**.

## Suggested Talking Points

- The pipeline keeps raw documents separate from extracted entities.
- Regex extraction handles deterministic indicators such as CVEs, URLs, hashes, IPs, and ATT&CK IDs.
- Enrichment adds NVD severity and MITRE ATT&CK context.
- Trend analysis separates social-only chatter from corroborated intelligence.
- Prioritization uses explainable scoring, not a black box.
- LLM output is constrained to source evidence and requires document IDs.

## Backup Plan

If live sources are blocked, the project uses local educational samples for CISA KEV, Reddit, NVD, and ATT&CK. This keeps the demo reproducible in classroom networks.
