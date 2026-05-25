# LLM-Based Threat Intelligence Gathering

Educational OSINT threat-intelligence pipeline for a penetration testing capstone project.

The project collects public cybersecurity content, cleans and normalizes it, extracts security entities, stores relationships for graph-style analysis, and generates analyst-oriented reports with source evidence.

## Current MVP

- RSS collection for security news and CERT/advisory sources
- CISA KEV JSON collection
- Reddit public-community collection through OAuth, with educational fallback samples
- Text cleaning and deduplication helpers
- Regex-based extraction for CVEs, IPs, domains, URLs, hashes, and MITRE ATT&CK technique IDs
- OSINT coverage scoring for source mix, reliability, linguistic diversity, and collection gaps
- SQLite storage for documents, entities, and relationships
- CLI commands for collection, extraction, and report generation
- React analyst command center
- Streamlit backup dashboard
- Neo4j Docker service prepared for the knowledge graph phase

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m cti_pipeline.cli init-db
python -m cti_pipeline.cli collect --source cisa_kev
python -m cti_pipeline.cli collect --source reddit
python -m cti_pipeline.cli collect --source rss  # optional live RSS sources
python -m cti_pipeline.cli extract
python -m cti_pipeline.cli enrich
python -m cti_pipeline.cli trends --days 3650
python -m cti_pipeline.cli prioritize --days 3650
python -m cti_pipeline.cli export-pack --days 3650
python -m cti_pipeline.cli report --days 3650
streamlit run dashboard/app.py
```

React command center:

```bash
python -m cti_pipeline.cli run-pipeline --source all --days 3650 --fresh --live-only --enrich-limit 8
python -m uvicorn cti_pipeline.api.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

One-command demo refresh:

```bash
python -m cti_pipeline.cli run-pipeline --source all --days 3650 --fresh --live-only --enrich-limit 8
```

Or use:

```bash
bash scripts/demo_run.sh
bash scripts/demo_full.sh
```

Optional graph services:

```bash
docker compose up -d neo4j
python -m cti_pipeline.cli sync-neo4j
```

Neo4j browser will be available at `http://localhost:7474` with username `neo4j` and password `capstonepassword`.

## Reddit OAuth

For live Reddit collection, create a Reddit app and set:

```bash
export REDDIT_CLIENT_ID=...
export REDDIT_CLIENT_SECRET=...
export REDDIT_USER_AGENT="pentest-capstone-cti-pipeline/0.1 by your_username"
```

If these variables are missing, the collector uses `data/sample_reddit_security.json` so demos and tests still work offline.
Use `--live-only` for presentation runs to disable this fallback and collect Reddit through OAuth or public subreddit JSON.

## Live Data Mode

For presentation data, run:

```bash
python -m cti_pipeline.cli run-pipeline --source all --days 3650 --fresh --live-only --enrich-limit 8
```

This backs up the current SQLite database, clears old rows, disables local fallback samples, collects reachable public sources, uses CISA's official KEV GitHub mirror if the main CISA endpoint blocks automated clients, enriches the top observed CVEs from NVD, and regenerates the report plus intelligence pack.

## Gemini Reports

LLM reporting is disabled by default. To enable Gemini through its OpenAI-compatible chat-completions endpoint:

```bash
export LLM_PROVIDER=openai_compatible
export LLM_MODEL=gemini-2.5-flash
export LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
export LLM_API_KEY=...
python -m cti_pipeline.cli llm-report --days 3650
```

The prompt requires JSON output, evidence document IDs, defensive recommendations, and caveats for uncorroborated social content.

## Presentation Highlights

- Mission Control summarizes high-risk findings and OSINT coverage posture.
- OSINT Coverage shows source reliability, source category mix, language mix, collection gaps, and recommended next collection moves.
- Priority Queue explains scoring, analyst verdict, source reliability, evidence, and recommended defensive actions.
- Knowledge Graph connects sources, documents, selected entities, and co-mentioned entities.
- Exports include a Markdown report, intelligence pack JSON, Sigma-style hunts, ATT&CK Navigator layer, and STIX-style bundle.

## Project Structure

```text
cti_pipeline/
  collectors/      Public-source collectors
  analysis/        Prioritization and source coverage scoring
  extractors/      Entity extraction and normalization
  storage/         SQLite and graph adapters
  reports/         Analyst report generation
config/            Source configuration
dashboard/         Streamlit interface
frontend/          React analyst command center
docs/              Architecture and project notes
scripts/           Demo and operational helper scripts
tests/             Unit tests
```

## Safety Scope

This project is defensive and educational. It collects only public, approved sources, avoids exploit automation, avoids malware downloads, and keeps evidence links for generated intelligence.
