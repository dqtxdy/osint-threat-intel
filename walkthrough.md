# Walkthrough - Knowledge Graph 2.0 Hardening

We have completed the presentation-risk hardening for CTI Knowledge Graph 2.0. All remaining issues identified from the database review have been resolved.

## Changes Made

### 1. Backend (`semantic.py`)
- **Type-Aware Analyst Takeaways**: Implemented specialized takeaways based on focus entity types (vendor, product, CVE, package, platform domain, script/path artifact, abused hosting, reference domain, and actual IOC).
- **Reference/Path Exclusions**: Restricted the global evaluation of malicious flag takeaways, evaluating direct edges to the focus entity, and mapping platform domains (`abuse.ch`) and path artifacts (`bin.sh`) to info/reference takeaways.
- **PhishTank Grouping Metadata**: Updated grouped PhishTank documents to correctly accumulate `source_count`, `source_types`, and populate `first_seen`/`last_seen` timestamps on virtual edges.
- **High-Fanout Visual Aggregation**: Enabled aggregation for `vendor` and `product` entities with $>12$ evidence documents. Only the top 12 individual documents are rendered, and the rest are grouped into virtual nodes by source name and year. Similarly, CVEs unique to grouped documents are collapsed into a `"Grouped CVEs (Year)"` node. Complete evidence-bound triples are maintained in the API response.
- **symfony.com Noise Suppression**: Filtered out generic `MENTIONS` and `CO_OCCURS` edges from the visual graph for reference domains unless they connect to a CVE, package, or advisory. Package list in the analyst takeaway is also deduplicated.

### 2. Frontend (`types.ts` & `App.tsx`)
- Extended `SemanticGraphResponse` TypeScript definition to support `total_evidence_count`, `displayed_evidence_count`, and `aggregation_applied` summary fields.
- Updated the "Analyst Summary Takeaway" panel to display the evidence record count (`"Showing X of Y evidence records"`) and an `"Aggregation Active"` badge when visual aggregation is applied.

---

## Verification Results

### Automated Tests
Run pytest in the workspace root:
```bash
python3 -m pytest tests
# 34 passed in 6.95s
```
All unit tests passed successfully, including the new unit test block `test_knowledge_graph_hardening_presentation_bugs` verifying our fixes.

### Real DB Probes Validation
We ran validation probes against the live SQLite DB:

1. **vendor Microsoft**
   - Takeaway: `"Vendor Microsoft appears across CISA KEV evidence in sampled vulnerability records affecting products such as .NET Framework, Active Directory, Configuration Manager and others. Prioritize review of active exploitation trends for Microsoft software."`
   - Metrics: `Nodes: 59, Edges: 102, Triples: 159`
   - Focus Risk: `medium`
   - Aggregation Applied: `True`

2. **product Windows**
   - Takeaway: `"Product Windows appears across sampled CISA KEV vulnerability records associated with Microsoft. Prioritize patch validation for actively exploited Windows CVEs."`
   - Metrics: `Nodes: 46, Edges: 90, Triples: 160`
   - Focus Risk: `medium`
   - Aggregation Applied: `True`

3. **domain symfony.com**
   - Takeaway: `"Domain symfony.com is identified as a reference or software project domain in collected CTI Security Advisories. It is not classified as malicious infrastructure."`
   - Metrics: `Nodes: 24, Edges: 32, Triples: 41`
   - Focus Risk: `info`
   - Aggregation Applied: `True`

4. **domain abuse.ch**
   - Takeaway: `"abuse.ch is a CTI platform/reference domain observed in ThreatFox/abuse.ch evidence, not the malicious IOC itself."`
   - Metrics: `Nodes: 21, Edges: 22, Triples: 48`
   - Focus Risk: `info`
   - Aggregation Applied: `True`

5. **domain bin.sh**
   - Takeaway: `"bin.sh appears to be a script/path artifact extracted from malware URLs; the actual observed infrastructure is the host/IP/full URL, not bin.sh as a standalone domain."`
   - Metrics: `Nodes: 14, Edges: 21, Triples: 120`
   - Focus Risk: `info`
   - Aggregation Applied: `True`
   - Selected Edges Predicates: `['CONTAINS_PATH_ARTIFACT']`

6. **domain weebly.com**
   - Takeaway: `"Domain weebly.com is an abused hosting platform observed in phishing campaigns; the infrastructure is shared, hosting legitimate content alongside malicious URLs."`
   - Metrics: `Nodes: 18, Edges: 17, Triples: 17`
   - Focus Risk: `info`
   - Aggregation Applied: `False`

7. **ip 45.155.69.173** (Actual IOC)
   - Takeaway: `"Malicious infrastructure indicator of compromise associated with malware family js.clearfake. Observed threat type: botnet_cc. Monitored nodes pose severe system intrusion risks."`
   - Metrics: `Nodes: 4, Edges: 3, Triples: 3`
   - Focus Risk: `high`
   - Aggregation Applied: `False`

### Frontend Build
Vite built successfully:
```bash
cd frontend && npm run build
# Built in 775ms
```
The large chunk warning is expected due to Vite's default threshold settings, but no typescript or compilation errors were reported.
