# Walkthrough - Threat Intelligence Source Expansion

We have successfully integrated and verified five new OSINT/CTI data sources (URLhaus, ThreatFox, FIRST EPSS, GitHub Security Advisories, and NCSC RSS feeds) into the Threat Intelligence pipeline.

## Changes Made

### 1. Source Configurations
* Registered the NCSC UK and NCSC NL advisories under `rss` in `config/sources.yml`.
* Configured `urlhaus`, `threatfox`, `github_advisories`, and `first_epss` under `config/sources.yml`.

### 2. Collector Implementation
* **URLhaus**: Implemented GET query to `https://urlhaus-api.abuse.ch/v1/urls/recent/` with optional header `Auth-Key`. Ingests malware metadata and URLs.
* **ThreatFox**: Implemented POST query to `https://threatfox-api.abuse.ch/api/v1/` with body `{ "query": "get_iocs", "days": 3 }` and header `Auth-Key`. Ingests network/host indicators.
* **GitHub Security Advisories**: Implemented GET query to `https://api.github.com/advisories` with custom `Accept`/`User-Agent` and optional `GITHUB_TOKEN` header. Ingests package and advisory information.

### 3. EPSS Enrichment
* **FIRST EPSS**: Implemented batch query logic fetching EPSS scores/percentiles for extracted CVEs from `https://api.first.org/data/v1/epss` in batches of 50. Integrated this into `cti_pipeline/enrichment/service.py` to store them under provider `first_epss`.

### 4. CLI & Reports
* Updated `cti_pipeline/cli.py` to expose the new collectors and print/log the new EPSS enrichment counts.
* Updated `cti_pipeline/reports/analyst_report.py` to display EPSS scores and percentiles alongside NVD CVSS ratings.
* Modified `cti_pipeline/extractors/entities.py` to safely catch `ValueError` during domain parsing of defanged URLs.

### 5. Fallback Samples
* Created educational fallback json samples under `data/`:
  * `data/sample_urlhaus.json`
  * `data/sample_threatfox.json`
  * `data/sample_github_advisories.json`
  * `data/sample_epss.json`

---

## Verification Results

### 1. Automated Unit Tests
Executed `python3 -m pytest tests`. All 18 tests passed successfully, including the newly added tests and the fixed PhishTank assertion:
```text
============================== 18 passed in 3.99s ==============================
```

### 2. Frontend Build
Executed `npm run build` in `frontend/`. Compiled cleanly in under 800ms:
```text
✓ built in 766ms
```

### 3. Pipeline End-to-End Run
Running the complete pipeline using a temporary SQLite database succeeded:
```bash
CTI_DB_PATH=/tmp/cti_demo.sqlite3 python3 -m cti_pipeline.cli run-pipeline --source all
```
Output:
```text
Pipeline complete
Collected: 1857 (32 inserted, 1825 duplicate)
Extraction: 1833 document(s), 8792 entity mention(s)
Enrichment: 47 CVE, 1 ATT&CK, 50 EPSS
Report: data/processed/latest_report.md
Intelligence pack: data/processed/intelligence_pack.json
```
The generated report correctly contains the newly formatted EPSS highlights:
```markdown
## Enrichment Highlights

- `CVE-2021-44228`: EPSS 0.943580000 (percentile 0.999640000)
- `CVE-2021-44228`: CRITICAL CVSS 10.0
- `CVE-2024-3400`: EPSS 0.943230000 (percentile 0.999540000)
```
