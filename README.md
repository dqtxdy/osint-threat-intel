# LLM-Based Threat Intelligence Gathering

Educational OSINT threat-intelligence pipeline for a penetration testing capstone project.

The project collects public cybersecurity content, cleans and normalizes it, extracts security entities, stores relationships for graph-style analysis, and generates analyst-oriented reports with source evidence.

## Current MVP

- RSS collection for security news and CERT/advisory sources (including NCSC UK and NCSC NL)
- CISA KEV JSON collection
- Reddit public-community collection through OAuth, with educational fallback samples
- Optional X recent-search collection through the official X API, with educational fallback samples
- PhishTank verified-online phishing feed collection
- Optional AlienVault OTX pulse collection through the official OTX API, with educational fallback samples
- URLhaus malware URL feed collection, with educational fallback samples
- ThreatFox IOC feed collection, with educational fallback samples
- GitHub Security Advisories collection, with educational fallback samples
- FIRST EPSS CVE enrichment, with educational fallback samples
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

## X API Collection

X collection uses the official X API v2 recent-search endpoint. Set a bearer token before running the pipeline:

```bash
export X_BEARER_TOKEN=...
python -m cti_pipeline.cli collect --source x --live-only
```

If `X_BEARER_TOKEN` is missing, normal demo runs use `data/sample_x_security.json`; `--live-only` disables that fallback and safely skips X when credentials are unavailable.

## PhishTank and OTX Feeds

PhishTank uses the official verified-online phishing database. For repeated automated use, set an app key:

```bash
export PHISHTANK_APP_KEY=...
python -m cti_pipeline.cli collect --source phishtank --live-only
```

AlienVault OTX uses the official OTX API and requires an API key:

```bash
export OTX_API_KEY=...
python -m cti_pipeline.cli collect --source otx --live-only
```

Normal demo runs use `data/sample_phishtank.json` and `data/sample_otx_pulses.json` if live access fails or credentials are unavailable. `--live-only` disables those fallbacks.

## URLhaus and ThreatFox Collection

URLhaus and ThreatFox collect recent malware distribution URLs and IOCs. To run live queries, set your abuse.ch API authentication key:

```bash
export ABUSECH_AUTH_KEY=...
# Or service-specific variables:
# export URLHAUS_AUTH_KEY=...
# export THREATFOX_AUTH_KEY=...

python -m cti_pipeline.cli collect --source urlhaus --live-only
python -m cti_pipeline.cli collect --source threatfox --live-only
```

If these keys are missing, the collectors fall back to `data/sample_urlhaus.json` and `data/sample_threatfox.json`.

## GitHub Security Advisories

GitHub Advisories collects reviewed vulnerabilities and packages. For higher rate limits, set your GitHub personal access token:

```bash
export GITHUB_TOKEN=...
python -m cti_pipeline.cli collect --source github_advisories --live-only
```

If no token is supplied, unauthenticated public access is used or it falls back to `data/sample_github_advisories.json`.

## FIRST EPSS Enrichment

The FIRST EPSS service enriches CVE entities with Exploit Prediction Scoring System scores and percentiles. It queries CVEs in batches:

```bash
python -m cti_pipeline.cli enrich
```

If the API is unreachable, it falls back to `data/sample_epss.json` maps.


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

This project is strictly defensive and educational.
- **Metadata and IOC collection only**: We do not download, store, or execute malware payloads or active exploits.
- **No automated exploit behavior**: This pipeline is only for threat monitoring and defense planning.
- **No scraping dashboards**: We only use official REST APIs, RSS feeds, or public/documented datasets. We do not scrape webpages or private panels (such as X web UI or AlienVault dashboard).
- **Verifiable links**: All generated reports link back to their official source evidence.

