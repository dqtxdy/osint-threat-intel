# Tasks

- [x] Create offline fallback sample data files under `data/`
- [x] Implement URLhaus collector in `cti_pipeline/collectors/urlhaus.py`
- [x] Implement ThreatFox collector in `cti_pipeline/collectors/threatfox.py`
- [x] Implement GitHub Security Advisories collector in `cti_pipeline/collectors/github_advisories.py`
- [x] Modify `config/sources.yml` to register new sources and RSS feeds
- [x] Modify `cti_pipeline/cli.py` to support new sources in the command line interface
- [x] Implement FIRST EPSS enrichment in `cti_pipeline/enrichment/first_epss.py`
- [x] Integrate FIRST EPSS into the enrichment service in `cti_pipeline/enrichment/service.py`
- [x] Update formatting and display of EPSS enrichments in `cti_pipeline/reports/analyst_report.py`
- [x] Fix existing PhishTank detail URL assertion in `tests/test_threat_feed_collectors.py`
- [x] Add unit tests for the new collectors and enrichment
- [x] Update project `README.md` documentation
- [x] Verify execution with tests and frontend compilation
