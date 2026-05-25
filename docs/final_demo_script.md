# Final Demo Script

## Setup

Run:

```bash
python3 -m cti_pipeline.cli run-pipeline --source all --days 3650 --fresh --live-only --enrich-limit 8
python3 -m uvicorn cti_pipeline.api.main:app --host 127.0.0.1 --port 8000 --reload
```

In another terminal:

```bash
cd frontend
npm run dev
```

Open `http://127.0.0.1:5173`.

## Flow

1. **Mission Control:** show document/entity/source counts, OSINT coverage posture, and corroboration matrix.
2. **OSINT Coverage:** show source mix, reliability, language diversity, gaps, and next collection moves.
3. **Priority Queue:** explain why critical CVEs score highly and open evidence.
4. **Threat Feed:** show collected OSINT sources and search/filter behavior.
5. **Entity Workbench:** select `CVE-2024-3400`, show enrichment, timeline, co-mentions, and evidence.
6. **Knowledge Graph:** show source/document/entity relationships.
7. **Reports:** show deterministic report and optionally Gemini report.
8. **Exports:** export Markdown, intelligence pack, Sigma-style hunts, ATT&CK Navigator layer, and STIX bundle.

## Key Talking Points

- The system does not trust social chatter blindly; it separates social-only and corroborated intelligence.
- The OSINT Coverage page directly addresses collection breadth, source reliability, and linguistic diversity.
- Live-only refresh disables local fallback samples; CISA KEV uses CISA's official GitHub mirror if the main CISA endpoint blocks automated clients.
- Every finding is evidence-backed.
- The LLM is constrained to provided source evidence and cannot replace deterministic extraction.
- The project avoids exploit automation, private scraping, and malware downloads.
