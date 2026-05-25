# Architecture

## Pipeline

```text
Collectors -> Raw Documents -> Cleaning -> Entity Extraction -> Enrichment -> Storage -> Reports/Dashboard
```

## MVP Storage

The first implementation uses SQLite because it is easy to demo and test. It stores graph-like relationships in an `edges` table, then Neo4j sync can be added without changing collectors or extractors.

## Knowledge Graph Model

Nodes:

- Document
- Source
- CVE
- Indicator
- Domain
- IPAddress
- Hash
- Malware
- ThreatActor
- Technique
- Product
- Report

Relationships:

- Source PUBLISHED Document
- Document MENTIONS Entity
- CVE AFFECTS Product
- CVE LISTED_IN CISA_KEV
- ThreatActor USES Malware
- ThreatActor USES_TECHNIQUE Technique
- Malware COMMUNICATES_WITH Indicator
- Report SUMMARIZES Document

Every relationship should include confidence, evidence, first seen, last seen, and source count where possible.

## Enrichment Layer

The enrichment stage runs after extraction:

- CVE entities are enriched from NVD, with a local fallback sample for repeatable demos.
- ATT&CK technique IDs are enriched with technique name, tactic, description, and reference URL.
- Enrichment payloads are stored in SQLite and synced into Neo4j entity nodes.

Demo queries:

```cypher
MATCH (c:CVE)-[:AFFECTS]->(p:Product)
RETURN c.value, p.value;

MATCH (d:Document)-[:MENTIONS]->(c:CVE)
RETURN d.title, c.value, c.enrichment_json;

MATCH (c:CVE)-[:LISTED_IN]->(:KEVEntry)
RETURN c.value;
```

## Trend Analysis

Trend analysis ranks entities by:

- total mentions
- distinct source count
- social mentions
- non-social mentions
- first seen and last seen timestamps
- confirmation label: `social only`, `official/structured only`, or `social + corroborated`

This supports a useful analyst workflow: identify entities that are noisy in social communities, then check whether they are corroborated by structured feeds, CERT advisories, or security news.
