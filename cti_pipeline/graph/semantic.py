from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlparse
from cti_pipeline.storage.sqlite_store import SQLiteStore

# Define noise domains as requested in the requirements
NOISE_DOMAINS = {
    "github.com",
    "cisa.gov",
    "mitre.org",
    "abuse.ch",
    "google.com",
    "microsoft.com",
    "nvd.nist.gov",
    "symfony.com",
    "bin.sh"
}

# Known feed platform/collector domains that should never be labeled as IOCs themselves
PLATFORM_DOMAINS = {
    "abuse.ch",
    "urlhaus.abuse.ch",
    "threatfox.abuse.ch"
}

# Script/path artifacts that are extracted as domains but are actually filenames
PATH_ARTIFACTS = {
    "bin.sh", "install.sh", "cache.py", "update.exe", "setup.sh", "run.sh",
    "init.sh", "config.php", "index.php", "main.py"
}

# Abused hosting platform domains
ABUSED_HOSTING_DOMAINS = {
    "weebly.com", "framer.app", "pages.dev", "netlify.app", "webflow.io"
}

def is_reference_domain(entity_type: str, value: str) -> bool:
    if entity_type != "domain":
        return False
    val = value.lower().strip()
    for domain in NOISE_DOMAINS:
        if val == domain or val.endswith("." + domain):
            return True
    return False

def is_platform_domain(value: str) -> bool:
    val = value.lower().strip()
    return val in PLATFORM_DOMAINS or val.endswith(".abuse.ch")

def is_path_artifact(value: str) -> bool:
    return value.lower().strip() in PATH_ARTIFACTS

def is_abused_hosting(value: str) -> bool:
    val = value.lower().strip()
    return val in ABUSED_HOSTING_DOMAINS or any(val.endswith("." + d) for d in ABUSED_HOSTING_DOMAINS)

def get_url_host(url_str: str) -> str:
    if not url_str:
        return ""
    try:
        parsed = urlparse(url_str)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]
        return host.lower().strip()
    except Exception:
        return ""

def get_source_reliability(source_type: str) -> str:
    source_type = source_type.lower()
    # Align source reliability: vendor and research are high in CTI contexts
    if source_type in ("structured_feed", "cert", "threat_feed", "vendor", "research"):
        return "high"
    if source_type in ("news", "rss"):
        return "medium"
    if source_type == "social":
        return "community"
    return "unknown"

def get_shared_document_ids(store: SQLiteStore, type1: str, val1: str, type2: str, val2: str, limit: int = 5) -> list[int]:
    with store.connect() as conn:
        rows = conn.execute(
            """
            SELECT de1.document_id
            FROM document_entities de1
            JOIN entities e1 ON e1.id = de1.entity_id
            JOIN document_entities de2 ON de2.document_id = de1.document_id
            JOIN entities e2 ON e2.id = de2.entity_id
            WHERE e1.entity_type = ? AND e1.normalized_value = ?
              AND e2.entity_type = ? AND e2.normalized_value = ?
            LIMIT ?
            """,
            (type1, val1, type2, val2, limit)
        ).fetchall()
        return [r["document_id"] for r in rows]

def build_semantic_graph(store: SQLiteStore, entity_type: str, value: str) -> dict[str, Any]:
    # 1. Resolve actual entity row using exact case-sensitive lookup first, then fallback
    with store.connect() as conn:
        entity_row = conn.execute(
            "SELECT * FROM entities WHERE entity_type = ? AND normalized_value = ?",
            (entity_type, value.strip())
        ).fetchone()
        if not entity_row:
            entity_row = conn.execute(
                "SELECT * FROM entities WHERE entity_type = ? AND LOWER(normalized_value) = LOWER(?)",
                (entity_type, value.strip())
            ).fetchone()

    if entity_row:
        normalized_value = entity_row["normalized_value"]
        display_value = entity_row["value"]
    else:
        # Fallback to general casing normalization rules
        if entity_type == "cve":
            normalized_value = value.strip().upper()
        elif entity_type == "domain":
            normalized_value = value.strip().lower()
        else:
            normalized_value = value.strip()
        display_value = value

    # 2. Retrieve evidence documents (limit 30)
    docs = store.entity_documents(entity_type, normalized_value, limit=30)
    doc_ids = [d["id"] for d in docs]

    # 3. Retrieve document-entity links for co-occurrence and metadata parsing
    doc_entities_map = {}
    if doc_ids:
        placeholders = ",".join("?" for _ in doc_ids)
        with store.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT de.document_id, e.entity_type, e.normalized_value, e.value, e.confidence as entity_conf,
                       de.confidence as edge_conf, de.evidence, de.first_seen, de.last_seen
                FROM document_entities de
                JOIN entities e ON de.entity_id = e.id
                WHERE de.document_id IN ({placeholders})
                """,
                doc_ids
            ).fetchall()
            for r in rows:
                doc_entities_map.setdefault(r["document_id"], []).append(r)

    nodes_dict: dict[str, dict[str, Any]] = {}
    edges_dict: dict[str, dict[str, Any]] = {}
    triples: list[dict[str, Any]] = []

    # Helper to map entity ID to "selected" focus node
    def get_node_id(etype: str, evalue: str) -> str:
        norm = evalue.strip().lower() if etype != "cve" else evalue.strip().upper()
        if etype == "cve":
            norm = evalue.strip().upper()
        elif etype == "domain":
            norm = evalue.strip().lower()
        else:
            norm = evalue.strip()
            
        if etype == entity_type and norm == normalized_value:
            return "selected"
        return f"entity-{etype}-{norm}"

    # Initialize Selected Focus Node
    nodes_dict["selected"] = {
        "id": "selected",
        "label": display_value,
        "kind": "selected_entity",
        "entity_type": entity_type,
        "value": display_value,
        "risk_level": "info",
        "confidence": 1.0,
        "evidence_count": len(docs),
        "first_seen": None,
        "last_seen": None,
        "badges": [entity_type.upper()],
        "description": f"Focused {entity_type} entity selected by the analyst.",
        "url": None
    }

    # Tracking sets for statistics
    source_names_set = set()
    source_types_set = set()
    ghsa_packages_set = set()
    caveats = []
    
    # Flags to determine summary takeaway
    is_kev = False
    kev_vendor = None
    kev_product = None
    is_phishing = False
    phish_target = None
    is_malware = False
    malware_family = None
    threat_type = None
    ghsa_id = None
    ghsa_package = None
    ghsa_severity = None

    # Helper to add node
    def add_node(nid: str, label: str, kind: str, etype: str | None = None, val: str | None = None,
                 risk: str = "info", conf: float = 1.0, desc: str = "", url: str | None = None, badges: list[str] | None = None):
        if nid not in nodes_dict:
            nodes_dict[nid] = {
                "id": nid,
                "label": label,
                "kind": kind,
                "entity_type": etype,
                "value": val,
                "risk_level": risk,
                "confidence": conf,
                "evidence_count": 0,
                "first_seen": None,
                "last_seen": None,
                "badges": badges or [],
                "description": desc,
                "url": url
            }
        else:
            if not nodes_dict[nid]["description"] and desc:
                nodes_dict[nid]["description"] = desc
            if not nodes_dict[nid]["url"] and url:
                nodes_dict[nid]["url"] = url
            if badges:
                for b in badges:
                    if b not in nodes_dict[nid]["badges"]:
                        nodes_dict[nid]["badges"].append(b)

    # Helper to add edge
    def add_edge(source: str, target: str, predicate: str, label: str, category: str, 
                 confidence: float, source_reliability: str, doc_id: int, rationale: str,
                 first_seen: str | None = None, last_seen: str | None = None):
        if source == target:
            return  # Avoid self-loops

        # Prioritize and suppress generic noise for reference domains
        if is_reference_domain(entity_type, value):
            if predicate in ("MENTIONS", "CO_OCCURS"):
                other = target if source == "selected" else source
                is_relevant = ("cve" in other or "package" in other or "advisory" in other)
                if not is_relevant:
                    return

        ekey = f"{source}->{target}:{predicate}"
        if ekey not in edges_dict:
            edges_dict[ekey] = {
                "id": ekey,
                "source": source,
                "target": target,
                "predicate": predicate,
                "label": label,
                "category": category,
                "confidence": confidence,
                "source_reliability": source_reliability,
                "evidence_document_ids": [doc_id],
                "evidence_count": 1,
                "rationale": rationale,
                "first_seen": first_seen,
                "last_seen": last_seen
            }
        else:
            edge = edges_dict[ekey]
            if doc_id not in edge["evidence_document_ids"]:
                edge["evidence_document_ids"].append(doc_id)
                edge["evidence_count"] += 1
            edge["confidence"] = max(edge["confidence"], confidence)
            if rationale and rationale not in edge["rationale"]:
                edge["rationale"] = edge["rationale"] + " | " + rationale
            if first_seen and (not edge["first_seen"] or first_seen < edge["first_seen"]):
                edge["first_seen"] = first_seen
            if last_seen and (not edge["last_seen"] or last_seen > edge["last_seen"]):
                edge["last_seen"] = last_seen

    # 4. Group PhishTank evidence documents by target brand if they are too numerous
    phishtank_docs = [d for d in docs if "phishtank" in d["source_id"].lower() or "phishtank" in d["source_name"].lower()]
    other_docs = [d for d in docs if d not in phishtank_docs]

    # Process other documents normally
    docs_to_process = other_docs
    
    # Check if PhishTank documents should be grouped to keep the graph presentation-readable
    phish_grouped = False
    if len(phishtank_docs) > 5:
        phish_grouped = True
        
        # Populate source metadata for grouped PhishTank documents
        for d in phishtank_docs:
            source_names_set.add(d["source_name"])
            source_types_set.add(d["source_type"])
            
        grouped_by_brand = {}
        for d in phishtank_docs:
            raw_meta = {}
            if d["raw_metadata"]:
                try: raw_meta = json.loads(d["raw_metadata"])
                except: pass
            brand = raw_meta.get("target") or "Unknown"
            # Suppress generic target brands
            if brand.lower() in ("other", "unknown", "unknown target", "n/a", "none", ""):
                brand = "Generic"
            grouped_by_brand.setdefault(brand, []).append(d)

        for brand, b_docs in grouped_by_brand.items():
            virtual_doc_id = f"doc-grouped-phishtank-{brand.lower().replace(' ', '_')}"
            doc_ids_list = [d["id"] for d in b_docs]
            first_doc = b_docs[0]
            reliability = get_source_reliability(first_doc["source_type"])

            # Compute min/max timestamps for the group
            b_times = [doc_item["published_at"] or doc_item["collected_at"] for doc_item in b_docs if doc_item["published_at"] or doc_item["collected_at"]]
            b_first = min(b_times) if b_times else None
            b_last = max(b_times) if b_times else None

            add_node(
                nid=virtual_doc_id,
                label=f"PhishTank: {brand} Campaigns ({len(b_docs)} URLs)",
                kind="document",
                etype="document",
                val=f"grouped-phishtank-{brand}",
                risk="high",
                conf=1.0,
                desc=f"Group of {len(b_docs)} PhishTank reports targeting brand '{brand}'.",
                badges=[first_doc["source_name"]]
            )
            
            source_node_id = f"source-{first_doc['source_id']}"
            add_node(source_node_id, first_doc["source_name"], "source", "source", first_doc["source_id"], "info", 1.0, "PhishTank Threat Feed", badges=[first_doc["source_type"].upper()])
            
            add_edge(
                source=source_node_id,
                target=virtual_doc_id,
                predicate="PUBLISHED",
                label="published",
                category="structural",
                confidence=1.0,
                source_reliability=reliability,
                doc_id=doc_ids_list[0],
                rationale=f"PhishTank threat feed published {len(b_docs)} reports targeting brand '{brand}'.",
                first_seen=b_first,
                last_seen=b_last
            )
            edges_dict[f"{source_node_id}->{virtual_doc_id}:PUBLISHED"]["evidence_document_ids"] = doc_ids_list
            edges_dict[f"{source_node_id}->{virtual_doc_id}:PUBLISHED"]["evidence_count"] = len(doc_ids_list)

            # Link virtual doc to Selected Focus Entity
            pred = "OBSERVED_PHISHING_URL"
            lbl = "observed phishing URL"
            cat = "phishing"
            if entity_type == "brand":
                pred = "TARGETS_BRAND"
                lbl = "targets brand"
            elif is_abused_hosting(value):
                pred = "ABUSED_HOSTING_PLATFORM"
                lbl = "abused hosting platform"
                
            add_edge(
                source=virtual_doc_id,
                target="selected",
                predicate=pred,
                label=lbl,
                category=cat,
                confidence=1.0,
                source_reliability=reliability,
                doc_id=doc_ids_list[0],
                rationale=f"Phishing campaign targeting brand '{brand}' was observed on focus entity {display_value}.",
                first_seen=b_first,
                last_seen=b_last
            )
            edges_dict[f"{virtual_doc_id}->selected:{pred}"]["evidence_document_ids"] = doc_ids_list
            edges_dict[f"{virtual_doc_id}->selected:{pred}"]["evidence_count"] = len(doc_ids_list)

            # Link virtual doc to Brand target node (if not Generic and not the focus brand itself)
            if brand != "Generic" and not (entity_type == "brand" and value.lower() == brand.lower()):
                brand_nid = get_node_id("brand", brand)
                add_node(brand_nid, brand, "related_entity", "brand", brand, "medium", 1.0, f"Phishing target brand: {brand}", badges=["BRAND"])
                add_edge(
                    source=virtual_doc_id,
                    target=brand_nid,
                    predicate="TARGETS_BRAND",
                    label="targets brand",
                    category="phishing",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_ids_list[0],
                    rationale=f"Phishing campaigns target brand '{brand}'."
                )
                edges_dict[f"{virtual_doc_id}->{brand_nid}:TARGETS_BRAND"]["evidence_document_ids"] = doc_ids_list
                edges_dict[f"{virtual_doc_id}->{brand_nid}:TARGETS_BRAND"]["evidence_count"] = len(doc_ids_list)

            # Process co-occurring hosting IPs and domains for virtual doc
            for d in b_docs:
                co_entities = doc_entities_map.get(d["id"], [])
                for ent in co_entities:
                    e_type = ent["entity_type"]
                    e_val = ent["normalized_value"]
                    e_disp = ent["value"]
                    
                    if e_type == "ip":
                        ip_nid = get_node_id("ip", e_val)
                        add_node(ip_nid, e_disp, "related_entity", "ip", e_disp, "high", 1.0, f"Phishing hosting IP: {e_disp}", badges=["PHISHING"])
                        add_edge(
                            source=virtual_doc_id,
                            target=ip_nid,
                            predicate="HOSTED_ON_IP",
                            label="hosted on IP",
                            category="phishing",
                            confidence=1.0,
                            source_reliability=reliability,
                            doc_id=d["id"],
                            rationale=f"Phishing site resolves to hosting IP address: {e_disp}."
                        )
                    elif e_type == "domain" and not is_abused_hosting(e_val) and get_node_id(e_type, e_val) != "selected":
                        # Add phishing domain
                        dom_nid = get_node_id("domain", e_val)
                        add_node(dom_nid, e_disp, "related_entity", "domain", e_disp, "high", 1.0, f"Phishing domain: {e_disp}", badges=["PHISHING"])
                        add_edge(
                            source=virtual_doc_id,
                            target=dom_nid,
                            predicate="OBSERVED_PHISHING_URL",
                            label="observed phishing URL",
                            category="phishing",
                            confidence=1.0,
                            source_reliability=reliability,
                            doc_id=d["id"],
                            rationale=f"Phishing domain {e_disp} observed in grouped campaigns."
                        )
    else:
        # Process PhishTank documents individually
        docs_to_process = docs

    for doc in docs_to_process:
        doc_id = doc["id"]
        doc_node_id = f"doc-{doc_id}"
        source_node_id = f"source-{doc['source_id']}"
        source_names_set.add(doc["source_name"])
        source_types_set.add(doc["source_type"])

        published_time = doc["published_at"] or doc["collected_at"]
        reliability = get_source_reliability(doc["source_type"])

        if doc["source_type"] == "social":
            caveats.append(f"Includes uncorroborated social intelligence from source: {doc['source_name']}.")

        # Parse raw metadata
        raw_meta = {}
        if doc["raw_metadata"]:
            try: raw_meta = json.loads(doc["raw_metadata"])
            except: pass

        # Create Source node
        add_node(
            nid=source_node_id,
            label=doc["source_name"],
            kind="source",
            etype="source",
            val=doc["source_id"],
            risk="info",
            conf=1.0,
            desc=f"{doc['source_name']} is a {doc['source_type']} CTI feed.",
            badges=[doc["source_type"].upper()]
        )

        doc_risk = "info"
        if doc["source_type"] in ("structured_feed", "threat_feed"):
            doc_risk = "high"
        elif doc["source_type"] == "vendor":
            doc_risk = "medium"

        # Create Document node
        add_node(
            nid=doc_node_id,
            label=doc["title"],
            kind="document",
            etype="document",
            val=str(doc_id),
            risk=doc_risk,
            conf=0.6 if doc["source_type"] == "social" else 1.0,
            desc=doc["body"][:280] + "..." if len(doc["body"]) > 280 else doc["body"],
            url=doc["url"],
            badges=[doc["source_name"]]
        )

        # Source PUBLISHED Evidence edge
        add_edge(
            source=source_node_id,
            target=doc_node_id,
            predicate="PUBLISHED",
            label="published",
            category="structural",
            confidence=1.0,
            source_reliability=reliability,
            doc_id=doc_id,
            rationale=f"OSINT source {doc['source_name']} published this intelligence document.",
            first_seen=published_time,
            last_seen=published_time
        )

        co_entities = doc_entities_map.get(doc_id, [])

        src_name_lower = doc["source_name"].lower()
        src_id_lower = doc["source_id"].lower()
        
        is_github = "github" in src_name_lower or "github" in src_id_lower
        is_cisa = "cisa" in src_name_lower or "cisa" in src_id_lower or "kev" in src_id_lower
        is_phish = "phishtank" in src_name_lower or "phishtank" in src_id_lower
        is_uhaus = "urlhaus" in src_name_lower or "urlhaus" in src_id_lower
        is_tfox = "threatfox" in src_name_lower or "threatfox" in src_id_lower

        if is_github:
            # GitHub Advisories semantics
            g_id = raw_meta.get("ghsa_id")
            cve_val = raw_meta.get("cve_id")
            severity = raw_meta.get("severity")
            ecosystem = raw_meta.get("ecosystem") # package info

            advisory_nid = doc_node_id
            if g_id:
                ghsa_id = g_id
                advisory_nid = f"entity-advisory-{g_id}"
                add_node(
                    nid=advisory_nid,
                    label=g_id,
                    kind="related_entity",
                    etype="advisory",
                    val=g_id,
                    risk="high" if severity in ("high", "critical") else "medium",
                    conf=1.0,
                    desc=f"GitHub Security Advisory {g_id}",
                    badges=["ADVISORY", severity.upper()] if severity else ["ADVISORY"]
                )
                add_edge(
                    source=doc_node_id,
                    target=advisory_nid,
                    predicate="ASSERTS",
                    label="asserts advisory",
                    category="structural",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"GitHub security notice asserts advisory {g_id}."
                )

            if cve_val:
                cve_nid = get_node_id("cve", cve_val)
                add_node(cve_nid, cve_val, "related_entity" if cve_nid != "selected" else "selected_entity", "cve", cve_val, "medium", 1.0, f"CVE Vulnerability {cve_val}")
                add_edge(
                    source=advisory_nid,
                    target=cve_nid,
                    predicate="HAS_CVE",
                    label="has CVE",
                    category="vulnerability",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Advisory {g_id or doc['title']} addresses vulnerability {cve_val}."
                )

            if ecosystem:
                ghsa_package = ecosystem
                packages = [p.strip() for p in ecosystem.split(",")]
                for pkg in packages:
                    if pkg and pkg.lower() != "unknown":
                        ghsa_packages_set.add(pkg)
                        pkg_nid = get_node_id("package", pkg)
                        add_node(pkg_nid, pkg, "related_entity" if pkg_nid != "selected" else "selected_entity", "package", pkg, "medium", 1.0, f"Software package: {pkg}")
                        add_edge(
                            source=advisory_nid,
                            target=pkg_nid,
                            predicate="AFFECTS_PACKAGE",
                            label="affects package",
                            category="vulnerability",
                            confidence=1.0,
                            source_reliability=reliability,
                            doc_id=doc_id,
                            rationale=f"Advisory affects package {pkg}."
                        )

            if severity:
                ghsa_severity = severity
                sev_nid = get_node_id("severity", severity)
                add_node(sev_nid, severity, "related_entity" if sev_nid != "selected" else "selected_entity", "severity", severity, "info", 1.0, f"Advisory severity: {severity}")
                add_edge(
                    source=advisory_nid,
                    target=sev_nid,
                    predicate="HAS_SEVERITY",
                    label="has severity",
                    category="vulnerability",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Security advisory has declared severity: {severity}."
                )

            # Suppress generic MENTIONS noise from GitHub Security Advisories
            for ent in co_entities:
                e_type = ent["entity_type"]
                e_val = ent["normalized_value"]
                e_disp = ent["value"]
                ent_nid = get_node_id(e_type, e_val)

                is_focus = (ent_nid == "selected")
                is_raw_cve = (e_type == "cve" and cve_val and e_val.upper() == cve_val.upper())
                is_ref_domain_relevant = (
                    e_type == "domain" and 
                    is_reference_domain(e_type, e_val) and 
                    (is_focus or entity_type in ("cve", "package") or "symfony" in value.lower() or "symfony" in e_val.lower())
                )

                # Keep ONLY explicitly relevant entities (the focus entity, primary CVE, or relevant reference domain)
                if is_focus or is_raw_cve or is_ref_domain_relevant:
                    if e_type == "domain" and is_reference_domain(e_type, e_val):
                        add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "info", 1.0, f"Reference domain: {e_disp}", badges=["REFERENCE"])
                        add_edge(
                            source=doc_node_id,
                            target=ent_nid,
                            predicate="REFERENCES_DOMAIN",
                            label="references domain",
                            category="noise/reference",
                            confidence=0.8,
                            source_reliability=reliability,
                            doc_id=doc_id,
                            rationale=f"GitHub advisory references project or documentation domain: {e_disp}."
                        )
                    else:
                        add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "medium", ent["entity_conf"], f"Entity {e_disp} observed in advisory.")
                        add_edge(
                            source=doc_node_id,
                            target=ent_nid,
                            predicate="MENTIONS",
                            label="mentions",
                            category="general",
                            confidence=0.8,
                            source_reliability=reliability,
                            doc_id=doc_id,
                            rationale=f"Advisory mentions entity {e_disp}."
                        )

        elif is_cisa:
            # CISA KEV semantics
            is_kev = True
            cve_val = raw_meta.get("cveID") or value
            vendor = raw_meta.get("vendorProject")
            product = raw_meta.get("product")
            ransomware = raw_meta.get("knownRansomwareCampaignUse")

            cve_nid = get_node_id("cve", cve_val)
            add_node(cve_nid, cve_val, "related_entity" if cve_nid != "selected" else "selected_entity", "cve", cve_val, "critical", 1.0, f"Known Exploited Vulnerability: {cve_val}")
            
            add_edge(
                source=doc_node_id,
                target=cve_nid,
                predicate="ASSERTS",
                label="asserts CVE",
                category="structural",
                confidence=1.0,
                source_reliability=reliability,
                doc_id=doc_id,
                rationale="CISA catalog document asserts KEV listing."
            )

            if vendor:
                kev_vendor = vendor
                vendor_nid = get_node_id("vendor", vendor)
                add_node(vendor_nid, vendor, "related_entity" if vendor_nid != "selected" else "selected_entity", "vendor", vendor, "medium", 1.0, f"Software vendor: {vendor}")
                add_edge(
                    source=cve_nid,
                    target=vendor_nid,
                    predicate="AFFECTS_VENDOR",
                    label="affects vendor",
                    category="vulnerability",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Exploited vulnerability {cve_val} affects software vendor {vendor}."
                )

            if product:
                kev_product = product
                product_nid = get_node_id("product", product)
                add_node(product_nid, product, "related_entity" if product_nid != "selected" else "selected_entity", "product", product, "medium", 1.0, f"Software product: {product}")
                add_edge(
                    source=cve_nid,
                    target=product_nid,
                    predicate="AFFECTS_PRODUCT",
                    label="affects product",
                    category="vulnerability",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Exploited vulnerability {cve_val} affects software product {product}."
                )

            kev_catalog_nid = get_node_id("kev_catalog", "KEV")
            add_node(kev_catalog_nid, "KEV Catalog", "related_entity" if kev_catalog_nid != "selected" else "selected_entity", "kev_catalog", "KEV", "critical", 1.0, "CISA Known Exploited Vulnerabilities Catalog")
            add_edge(
                source=cve_nid,
                target=kev_catalog_nid,
                predicate="LISTED_IN_KEV",
                label="listed in KEV",
                category="vulnerability",
                confidence=1.0,
                source_reliability=reliability,
                doc_id=doc_id,
                rationale=f"Vulnerability {cve_val} is cataloged under CISA KEV as actively exploited in the wild."
            )

            if ransomware and ransomware.strip() != "":
                if ransomware.lower() != "unknown":
                    rans_nid = get_node_id("ransomware_use", ransomware)
                    add_node(rans_nid, f"Ransomware: {ransomware}", "related_entity" if rans_nid != "selected" else "selected_entity", "ransomware_use", ransomware, "critical", 1.0, "Associated ransomware use status")
                    add_edge(
                        source=cve_nid,
                        target=rans_nid,
                        predicate="HAS_RANSOMWARE_USE",
                        label="ransomware use",
                        category="vulnerability",
                        confidence=1.0,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Vulnerability {cve_val} has confirmed ransomware campaign association: {ransomware}."
                    )

            for ent in co_entities:
                e_type = ent["entity_type"]
                e_val = ent["normalized_value"]
                e_disp = ent["value"]
                if e_type not in ("cve", "vendor", "product", "kev_catalog", "ransomware_use"):
                    ent_nid = get_node_id(e_type, e_val)
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "high", ent["entity_conf"], f"Entity mentioned alongside KEV record.")
                    add_edge(
                        source=cve_nid,
                        target=ent_nid,
                        predicate="MENTIONS",
                        label="mentions",
                        category="general",
                        confidence=1.0,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"KEV record mentions co-occurring entity {e_disp}."
                    )

        elif is_phish:
            # PhishTank phishing infrastructure semantics
            is_phishing = True
            target = raw_meta.get("target")

            # Suppress generic target brands
            if target and target.lower() not in ("other", "unknown", "unknown target", "n/a", "none") and target.strip() != "":
                phish_target = target
                brand_nid = get_node_id("brand", target)
                add_node(brand_nid, target, "related_entity" if brand_nid != "selected" else "selected_entity", "brand", target, "medium", 1.0, f"Phishing target brand: {target}", badges=["BRAND"])
                add_edge(
                    source=doc_node_id,
                    target=brand_nid,
                    predicate="TARGETS_BRAND",
                    label="targets brand",
                    category="phishing",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Phishing campaign is targeting credentials of brand: {target}."
                )

            # Map domains, URLs, IPs as phishing infrastructure
            for ent in co_entities:
                e_type = ent["entity_type"]
                e_val = ent["normalized_value"]
                e_disp = ent["value"]
                
                ent_nid = get_node_id(e_type, e_val)
                
                # Check for abused hosting platform vs direct phishing brand
                if e_type == "domain" and is_abused_hosting(e_val):
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "medium", 1.0, f"Abused hosting platform: {e_disp}", badges=["HOSTING"])
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="ABUSED_HOSTING_PLATFORM",
                        label="abused hosting platform",
                        category="phishing",
                        confidence=1.0,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Phishing page is hosted on shared platform: {e_disp}."
                    )
                elif e_type in ("domain", "url"):
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "high", 1.0, f"Phishing infrastructure URL/domain: {e_disp}", badges=["PHISHING"])
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="OBSERVED_PHISHING_URL",
                        label="observed phishing URL",
                        category="phishing",
                        confidence=1.0,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Phishing feed observed active credential theft site on {e_disp}."
                    )
                elif e_type == "ip":
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "high", 1.0, f"Phishing hosting IP address: {e_disp}", badges=["PHISHING"])
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="HOSTED_ON_IP",
                        label="hosted on IP",
                        category="phishing",
                        confidence=1.0,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Phishing domain was resolved hosting on IP address: {e_disp}."
                    )

        elif is_uhaus or is_tfox:
            # URLhaus / ThreatFox malware IOC semantics
            is_malware = True
            m_family = raw_meta.get("malware_family")
            t_type = raw_meta.get("threat_type") or raw_meta.get("threat")
            
            raw_ioc = str(raw_meta.get("ioc", "")).lower().strip()
            raw_url = str(raw_meta.get("url", "")).lower().strip()
            raw_host = get_url_host(raw_url)

            if m_family and m_family.lower() not in ("unknown", "n/a") and m_family.strip() != "":
                malware_family = m_family
                mal_nid = get_node_id("malware_family", m_family)
                add_node(mal_nid, m_family, "related_entity" if mal_nid != "selected" else "selected_entity", "malware_family", m_family, "critical", 1.0, f"Malware Family: {m_family}", badges=["MALWARE"])
                add_edge(
                    source=doc_node_id,
                    target=mal_nid,
                    predicate="ASSOCIATED_WITH_MALWARE",
                    label="associated with malware",
                    category="malware",
                    confidence=1.0,
                    source_reliability=reliability,
                    doc_id=doc_id,
                    rationale=f"Malicious indicator belongs to malware family: {m_family}."
                )

            if t_type:
                threat_type = t_type

            # Map observables, filtering platform domains and path artifacts
            for ent in co_entities:
                e_type = ent["entity_type"]
                e_val = ent["normalized_value"]
                e_disp = ent["value"]
                ent_nid = get_node_id(e_type, e_val)

                is_platform = is_platform_domain(e_val)
                is_path = is_path_artifact(e_val)

                if is_platform:
                    # Known platform domain - label it low-risk reference only
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "info", 1.0, f"Platform/Collector: {e_disp}", badges=["REFERENCE"])
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="REFERENCES_DOMAIN",
                        label="references platform",
                        category="noise/reference",
                        confidence=0.8,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"CTI report references feed or analyzer platform domain: {e_disp}."
                    )
                elif is_path:
                    # Skip treating it as malware domain IOC
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "low", 1.0, f"Script/File artifact: {e_disp}")
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="CONTAINS_PATH_ARTIFACT",
                        label="contains path artifact",
                        category="general",
                        confidence=0.8,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Report indicates document contains script or path artifact: {e_disp}."
                    )
                else:
                    # Standard domain/IP/hash parsing
                    if is_uhaus:
                        if is_path_artifact(e_val) or is_platform_domain(e_val) or is_reference_domain(e_type, e_val):
                            is_actual_ioc = False
                        else:
                            is_actual_ioc = (e_val == raw_url or e_val == raw_host or ent_nid == "selected")
                        if is_actual_ioc:
                            add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "high", 1.0, f"Malware domain/observable: {e_disp}", badges=["MALWARE"])
                            add_edge(
                                source=doc_node_id,
                                target=ent_nid,
                                predicate="OBSERVED_MALWARE_URL",
                                label="observed malware URL",
                                category="malware",
                                confidence=1.0,
                                source_reliability=reliability,
                                doc_id=doc_id,
                                rationale=f"URLhaus threat feed reported malware download hosting on {e_disp}."
                            )
                        else:
                            # incidental co-occurring entity
                            add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "low", ent["entity_conf"], f"Entity mentioned: {e_disp}")
                            add_edge(
                                source=doc_node_id,
                                target=ent_nid,
                                predicate="MENTIONS",
                                label="mentions",
                                category="general",
                                confidence=0.6,
                                source_reliability=reliability,
                                doc_id=doc_id,
                                rationale=f"URLhaus report mentions entity {e_disp}."
                            )
                    else:  # is_tfox
                        if is_path_artifact(e_val) or is_platform_domain(e_val) or is_reference_domain(e_type, e_val):
                            is_actual_ioc = False
                        else:
                            is_actual_ioc = (e_val == raw_ioc or ent_nid == "selected")
                        if is_actual_ioc:
                            add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "high", 1.0, f"Indicator of Compromise (IOC): {e_disp}", badges=["IOC"])
                            add_edge(
                                source=doc_node_id,
                                target=ent_nid,
                                predicate="OBSERVED_IOC",
                                label="observed IOC",
                                category="malware",
                                confidence=float(raw_meta.get("confidence", 75)) / 100.0,
                                source_reliability=reliability,
                                doc_id=doc_id,
                                rationale=f"ThreatFox registered IOC {e_disp} (threat type: {t_type or 'unknown'})."
                            )
                        else:
                            add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "low", ent["entity_conf"], f"Entity mentioned: {e_disp}")
                            add_edge(
                                source=doc_node_id,
                                target=ent_nid,
                                predicate="MENTIONS",
                                label="mentions",
                                category="general",
                                confidence=0.6,
                                source_reliability=reliability,
                                doc_id=doc_id,
                                rationale=f"ThreatFox report mentions entity {e_disp}."
                            )

        else:
            # News/social/research / rss general mentions
            for ent in co_entities:
                e_type = ent["entity_type"]
                e_val = ent["normalized_value"]
                e_disp = ent["value"]
                ent_nid = get_node_id(e_type, e_val)

                # Check if it is a reference noise domain
                if e_type == "domain" and is_reference_domain(e_type, e_val):
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "info", 1.0, f"Reference domain: {e_disp}", badges=["REFERENCE"])
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="REFERENCES_DOMAIN",
                        label="references domain",
                        category="noise/reference",
                        confidence=0.5,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"Article references common infrastructure or utility domain: {e_disp}."
                    )
                else:
                    add_node(ent_nid, e_disp, "related_entity" if ent_nid != "selected" else "selected_entity", e_type, e_disp, "low" if doc["source_type"] == "social" else "medium", ent["entity_conf"], f"Entity mentioned: {e_disp}")
                    add_edge(
                        source=doc_node_id,
                        target=ent_nid,
                        predicate="MENTIONS",
                        label="mentions",
                        category="general",
                        confidence=0.5 if doc["source_type"] == "social" else 0.8,
                        source_reliability=reliability,
                        doc_id=doc_id,
                        rationale=f"CTI report mentions security entity {e_disp}."
                    )

    # 5. Connect co-occurring entities in general if not already covered by document paths
    # Query actual shared document IDs instead of using doc_id = -1 fallback
    co_occurrences = store.co_occurring_entities(entity_type, normalized_value, limit=15)
    for co in co_occurrences:
        co_type = co["entity_type"]
        co_val = co["normalized_value"]
        co_disp = co["value"] if "value" in co.keys() else co_val
        co_nid = get_node_id(co_type, co_val)

        # Skip if already exists or is a path artifact
        if co_nid in nodes_dict or is_path_artifact(co_val):
            continue

        # Get actual shared documents
        shared_docs = get_shared_document_ids(store, entity_type, normalized_value, co_type, co_val, limit=5)
        if not shared_docs:
            continue  # do not emit if no actual shared documents exists

        # Add node as related
        add_node(co_nid, co_disp, "related_entity", co_type, co_disp, "info", 0.7, f"Co-occurring entity {co_disp}.")
        
        # Determine predicate
        pred = "CO_OCCURS"
        label = "co-occurs"
        cat = "general"
        if entity_type == "vendor" and co_type == "product":
            pred = "AFFECTS_PRODUCT"
            label = "affects product"
            cat = "vulnerability"
        
        add_edge(
            source="selected",
            target=co_nid,
            predicate=pred,
            label=label,
            category=cat,
            confidence=0.7,
            source_reliability="high",
            doc_id=shared_docs[0],
            rationale=f"Co-occurs with {display_value} in {co['shared_documents']} shared documents."
        )
        
        # Update the edge's evidence_document_ids with all actual shared docs!
        ekey = f"selected->{co_nid}:{pred}"
        if ekey in edges_dict:
            edges_dict[ekey]["evidence_document_ids"] = shared_docs
            edges_dict[ekey]["evidence_count"] = len(shared_docs)

    # 6. Post-process nodes to calculate dynamic risk levels and update first_seen/last_seen from edges
    for edge in edges_dict.values():
        src = edge["source"]
        tgt = edge["target"]

        for nid in (src, tgt):
            if nid in nodes_dict:
                node = nodes_dict[nid]
                if edge["first_seen"]:
                    if not node["first_seen"] or edge["first_seen"] < node["first_seen"]:
                        node["first_seen"] = edge["first_seen"]
                if edge["last_seen"]:
                    if not node["last_seen"] or edge["last_seen"] > node["last_seen"]:
                        node["last_seen"] = edge["last_seen"]

                if node["kind"] == "related_entity" and edge["category"] != "structural":
                    node["evidence_count"] += edge["evidence_count"]

        # Push risk levels dynamically based on semantics
        if edge["category"] == "malware":
            for nid in (src, tgt):
                if nid in nodes_dict and nodes_dict[nid]["kind"] == "related_entity":
                    curr_risk = nodes_dict[nid]["risk_level"]
                    if curr_risk not in ("critical", "high"):
                        nodes_dict[nid]["risk_level"] = "high"
        elif edge["category"] == "phishing":
            for nid in (src, tgt):
                if nid in nodes_dict and nodes_dict[nid]["kind"] == "related_entity":
                    curr_risk = nodes_dict[nid]["risk_level"]
                    if curr_risk not in ("critical", "high"):
                        nodes_dict[nid]["risk_level"] = "high"
        elif edge["category"] == "vulnerability":
            for nid in (src, tgt):
                if nid in nodes_dict and nodes_dict[nid]["kind"] == "related_entity":
                    curr_risk = nodes_dict[nid]["risk_level"]
                    # Elevate KEV CVE to critical
                    if nodes_dict[nid]["entity_type"] == "cve" and (is_kev or "KEV" in nodes_dict[nid]["badges"]):
                        nodes_dict[nid]["risk_level"] = "critical"
                    elif curr_risk == "info":
                        nodes_dict[nid]["risk_level"] = "medium"

    final_nodes = list(nodes_dict.values())
    final_edges = list(edges_dict.values())

    # 7. Restrict Risk propagation on Selected Focus Node based on connected predicates
    focus_risk = "info"
    focus_edges = [e for e in final_edges if e["source"] == "selected" or e["target"] == "selected"]
    
    has_malicious = any(e["predicate"] in ("OBSERVED_IOC", "OBSERVED_MALWARE_URL", "OBSERVED_PHISHING_URL", "HOSTED_ON_IP") for e in focus_edges)
    has_kev_listing = any(e["predicate"] == "LISTED_IN_KEV" for e in focus_edges) or (entity_type == "cve" and is_kev)
    has_vulnerability = any(e["predicate"] in ("AFFECTS_PACKAGE", "HAS_CVE", "AFFECTS_VENDOR", "AFFECTS_PRODUCT") for e in focus_edges)
    has_reference = any(e["predicate"] == "REFERENCES_DOMAIN" for e in focus_edges)
    
    if has_kev_listing:
        focus_risk = "critical"
    elif has_malicious:
        # If it is a known reference/noise/platform domain or path artifact, demote risk to info
        if is_reference_domain(entity_type, value) or is_platform_domain(value) or is_path_artifact(value):
            focus_risk = "info"
        else:
            focus_risk = "high"
    elif has_vulnerability:
        focus_risk = "medium"
    elif has_reference:
        focus_risk = "info"
        
    nodes_dict["selected"]["risk_level"] = focus_risk

    # 8. Generate Triples
    for edge in final_edges:
        sub_node = nodes_dict.get(edge["source"])
        obj_node = nodes_dict.get(edge["target"])
        if sub_node and obj_node:
            triples.append({
                "subject": sub_node["label"],
                "predicate": edge["predicate"],
                "object": obj_node["label"],
                "evidence": edge["evidence_document_ids"],
                "confidence": edge["confidence"],
                "rationale": edge["rationale"]
            })

    # Helper to extract the year of a CVE
    def get_cve_year(cve_str: str) -> str:
        parts = cve_str.split("-")
        if len(parts) > 1:
            return parts[1]
        return "Unknown"

    # Helper to extract the year from doc
    def get_doc_year(doc_item: dict[str, Any]) -> str:
        raw_meta_dict = {}
        if doc_item["raw_metadata"]:
            try: raw_meta_dict = json.loads(doc_item["raw_metadata"])
            except: pass
        cve_id_str = raw_meta_dict.get("cveID") or raw_meta_dict.get("cve_id")
        if cve_id_str and cve_id_str.upper().startswith("CVE-"):
            return get_cve_year(cve_id_str)
        date_str = doc_item["published_at"] or doc_item["collected_at"]
        if date_str:
            return date_str[:4]
        return "Unknown"

    # 8.5 Visual Aggregation
    aggregation_applied = False
    total_evidence_count = len(docs)
    displayed_evidence_count = total_evidence_count

    # Determine visual limits based on focus mode
    is_compact_focus = is_platform_domain(value) or is_path_artifact(value) or is_reference_domain(entity_type, value)
    
    if is_compact_focus or (entity_type in ("vendor", "product") and len(docs) > 12):
        aggregation_applied = True
        
        # Determine how many evidence documents to keep individually
        doc_limit = 5 if is_compact_focus else 12
        displayed_evidence_count = min(doc_limit, len(docs))
        
        keep_docs = docs[:doc_limit]
        keep_doc_ids = {d["id"] for d in keep_docs}
        group_docs = docs[doc_limit:]
        
        # Build mapping of doc_id to virtual grouped node ID
        doc_to_virtual = {}
        virtual_nodes = {}
        
        # Count documents per group to display in the label
        group_counts = {}
        for d in group_docs:
            yr = get_doc_year(d)
            key = (d["source_name"], yr)
            group_counts[key] = group_counts.get(key, 0) + 1

        for d in group_docs:
            yr = get_doc_year(d)
            key = (d["source_name"], yr)
            s_name, yr_val = key
            virtual_id = f"doc-grouped-{s_name.lower().replace(' ', '_')}-{yr_val}"
            doc_to_virtual[d["id"]] = virtual_id
            
            if virtual_id not in virtual_nodes:
                virtual_nodes[virtual_id] = {
                    "id": virtual_id,
                    "label": f"Grouped {s_name} {yr_val} Evidence ({group_counts[key]} records)",
                    "kind": "document",
                    "entity_type": "document",
                    "value": f"grouped-{s_name.lower().replace(' ', '_')}-{yr_val}",
                    "risk_level": "medium" if "vendor" in d["source_type"].lower() else "high",
                    "confidence": 1.0,
                    "evidence_count": group_counts[key],
                    "first_seen": None,
                    "last_seen": None,
                    "badges": [s_name],
                    "description": f"Group of {group_counts[key]} evidence records from {s_name} for year {yr_val}.",
                    "url": None
                }

        # Collapsing related entities
        cve_to_virtual = {}
        virtual_cve_nodes = {}
        
        ioc_to_virtual = {}
        virtual_ioc_nodes = {}

        if is_compact_focus:
            # Compact mode visual aggregation for platform/path/reference entities
            urlhaus_hosts = [n for n in final_nodes if n["kind"] == "related_entity" and n["entity_type"] in ("ip", "domain", "url", "sha256") and (any("MALWARE" in b for b in n["badges"]) or "urlhaus" in n["description"].lower())]
            threatfox_iocs = [n for n in final_nodes if n["kind"] == "related_entity" and n["entity_type"] in ("ip", "domain", "url", "sha256") and (any("IOC" in b for b in n["badges"]) or "threatfox" in n["description"].lower())]
            malware_families = [n for n in final_nodes if n["kind"] == "related_entity" and n["entity_type"] == "malware_family"]
            
            # Collapse URLhaus Hosts beyond 5
            if len(urlhaus_hosts) > 5:
                group_hosts = urlhaus_hosts[5:]
                virtual_host_id = "entity-grouped-urlhaus-hosts"
                virtual_ioc_nodes[virtual_host_id] = {
                    "id": virtual_host_id,
                    "label": f"Grouped URLhaus Hosts ({len(group_hosts)})",
                    "kind": "related_entity",
                    "entity_type": "domain",
                    "value": f"Grouped URLhaus Hosts ({len(group_hosts)})",
                    "risk_level": "high",
                    "confidence": 1.0,
                    "evidence_count": len(group_hosts),
                    "first_seen": None,
                    "last_seen": None,
                    "badges": ["MALWARE", "GROUPED"],
                    "description": f"Group of {len(group_hosts)} URLhaus host/observable entities.",
                    "url": None
                }
                for n in group_hosts:
                    ioc_to_virtual[n["id"]] = virtual_host_id
                    
            # Collapse ThreatFox IOCs beyond 5
            if len(threatfox_iocs) > 5:
                group_iocs = threatfox_iocs[5:]
                virtual_ioc_id = "entity-grouped-threatfox-iocs"
                virtual_ioc_nodes[virtual_ioc_id] = {
                    "id": virtual_ioc_id,
                    "label": f"Grouped ThreatFox IOCs ({len(group_iocs)})",
                    "kind": "related_entity",
                    "entity_type": "domain",
                    "value": f"Grouped ThreatFox IOCs ({len(group_iocs)})",
                    "risk_level": "high",
                    "confidence": 1.0,
                    "evidence_count": len(group_iocs),
                    "first_seen": None,
                    "last_seen": None,
                    "badges": ["IOC", "GROUPED"],
                    "description": f"Group of {len(group_iocs)} ThreatFox indicator entities.",
                    "url": None
                }
                for n in group_iocs:
                    ioc_to_virtual[n["id"]] = virtual_ioc_id

            # Collapse Malware Families beyond 5
            if len(malware_families) > 5:
                group_fams = malware_families[5:]
                virtual_fam_id = "entity-grouped-malware-families"
                virtual_ioc_nodes[virtual_fam_id] = {
                    "id": virtual_fam_id,
                    "label": f"Grouped Malware Families ({len(group_fams)})",
                    "kind": "related_entity",
                    "entity_type": "malware_family",
                    "value": f"Grouped Malware Families ({len(group_fams)})",
                    "risk_level": "critical",
                    "confidence": 1.0,
                    "evidence_count": len(group_fams),
                    "first_seen": None,
                    "last_seen": None,
                    "badges": ["MALWARE", "GROUPED"],
                    "description": f"Group of {len(group_fams)} malware families.",
                    "url": None
                }
                for n in group_fams:
                    ioc_to_virtual[n["id"]] = virtual_fam_id

            # Collapse all other related entities by entity_type beyond 3
            other_by_type = {}
            for n in final_nodes:
                if n["kind"] == "related_entity" and n["id"] != "selected" and n["id"] not in ioc_to_virtual:
                    etype = n.get("entity_type") or "other"
                    other_by_type.setdefault(etype, []).append(n)
            
            etype_labels = {
                "cve": "CVEs",
                "package": "Packages",
                "malware_family": "Malware Families",
                "ip": "IPs",
                "domain": "Domains",
                "url": "URLs",
                "sha256": "File Hashes (SHA256)",
                "sha1": "File Hashes (SHA1)",
                "md5": "File Hashes (MD5)",
                "advisory": "Advisories",
                "severity": "Severities"
            }
            
            for etype, nodes_list in other_by_type.items():
                if len(nodes_list) > 2:
                    group_nodes = nodes_list[2:]
                    etype_label = etype_labels.get(etype, etype.replace('_', ' ').title())
                    virtual_id = f"entity-grouped-{etype}"
                    
                    virtual_ioc_nodes[virtual_id] = {
                        "id": virtual_id,
                        "label": f"Grouped {etype_label} ({len(group_nodes)})",
                        "kind": "related_entity",
                        "entity_type": etype,
                        "value": f"Grouped {etype_label} ({len(group_nodes)})",
                        "risk_level": "high" if etype in ("cve", "malware_family", "ip", "domain", "url", "sha256", "sha1", "md5") else "info",
                        "confidence": 1.0,
                        "evidence_count": len(group_nodes),
                        "first_seen": None,
                        "last_seen": None,
                        "badges": [etype.upper(), "GROUPED"],
                        "description": f"Group of {len(group_nodes)} {etype_label} entities.",
                        "url": None
                    }
                    for n in group_nodes:
                        ioc_to_virtual[n["id"]] = virtual_id

        else:
            # High-fanout mode visual aggregation for vendor/product (default)
            # Identify CVEs that are only referenced in grouped documents
            keep_cves = set()
            for d in keep_docs:
                for r in doc_entities_map.get(d["id"], []):
                    if r["entity_type"] == "cve":
                        keep_cves.add(r["normalized_value"].upper())

            group_only_cves = set()
            cve_to_year = {}
            for d in group_docs:
                for r in doc_entities_map.get(d["id"], []):
                    if r["entity_type"] == "cve":
                        cve_val = r["normalized_value"].upper()
                        if cve_val not in keep_cves:
                            group_only_cves.add(cve_val)
                            cve_to_year[cve_val] = get_cve_year(cve_val)

            # Map group-only CVEs to virtual CVE nodes
            for cve_val in group_only_cves:
                yr_val = cve_to_year[cve_val]
                virtual_cve_id = f"entity-grouped-cve-{yr_val}"
                cve_to_virtual[cve_val] = virtual_cve_id
                if virtual_cve_id not in virtual_cve_nodes:
                    virtual_cve_nodes[virtual_cve_id] = {
                        "id": virtual_cve_id,
                        "label": f"Grouped CVEs ({yr_val})",
                        "kind": "related_entity",
                        "entity_type": "cve",
                        "value": f"Grouped CVEs ({yr_val})",
                        "risk_level": "critical",
                        "confidence": 1.0,
                        "evidence_count": 0,
                        "first_seen": None,
                        "last_seen": None,
                        "badges": ["CVE", yr_val],
                        "description": f"Group of CVEs from year {yr_val}.",
                        "url": None
                    }

        # Rebuild final_nodes: filter out individual document/CVE/IOC nodes that have been grouped
        new_nodes = []
        for n in final_nodes:
            # Skip individual document node if grouped
            if n["kind"] == "document" and n["id"].startswith("doc-") and not n["id"].startswith("doc-grouped-"):
                doc_id_str = n["id"][4:]
                if doc_id_str.isdigit() and int(doc_id_str) not in keep_doc_ids:
                    continue
            # Skip CVE node if grouped
            if n["entity_type"] == "cve" and n["id"].startswith("entity-cve-"):
                cve_val = n["value"].upper()
                if cve_val in cve_to_virtual:
                    continue
            # Skip IOC/malware/family node if grouped in compact mode
            if is_compact_focus and n["id"] in ioc_to_virtual:
                continue
            new_nodes.append(n)

        # Add virtual nodes to list
        new_nodes.extend(virtual_nodes.values())
        new_nodes.extend(virtual_cve_nodes.values())
        new_nodes.extend(virtual_ioc_nodes.values())

        # Rebuild edges mapping to virtual nodes
        new_edges = {}
        for e in final_edges:
            src = e["source"]
            tgt = e["target"]
            pred = e["predicate"]
            
            new_src = src
            new_tgt = tgt
            
            # Map source/target document IDs
            if src.startswith("doc-") and not src.startswith("doc-grouped-"):
                doc_id_str = src[4:]
                if doc_id_str.isdigit() and int(doc_id_str) not in keep_doc_ids:
                    new_src = doc_to_virtual[int(doc_id_str)]
            if tgt.startswith("doc-") and not tgt.startswith("doc-grouped-"):
                doc_id_str = tgt[4:]
                if doc_id_str.isdigit() and int(doc_id_str) not in keep_doc_ids:
                    new_tgt = doc_to_virtual[int(doc_id_str)]

            # Map source/target CVE IDs
            if src.startswith("entity-cve-"):
                cve_val = src[11:].upper()
                if cve_val in cve_to_virtual:
                    new_src = cve_to_virtual[cve_val]
            if tgt.startswith("entity-cve-"):
                cve_val = tgt[11:].upper()
                if cve_val in cve_to_virtual:
                    new_tgt = cve_to_virtual[cve_val]

            # Map source/target IOC/family IDs
            if is_compact_focus:
                if src in ioc_to_virtual:
                    new_src = ioc_to_virtual[src]
                if tgt in ioc_to_virtual:
                    new_tgt = ioc_to_virtual[tgt]

            if new_src == new_tgt:
                continue

            ekey = f"{new_src}->{new_tgt}:{pred}"
            if ekey not in new_edges:
                new_edges[ekey] = {
                    "id": ekey,
                    "source": new_src,
                    "target": new_tgt,
                    "predicate": pred,
                    "label": e["label"],
                    "category": e["category"],
                    "confidence": e["confidence"],
                    "source_reliability": e["source_reliability"],
                    "evidence_document_ids": list(e["evidence_document_ids"]),
                    "evidence_count": e["evidence_count"],
                    "rationale": e["rationale"],
                    "first_seen": e["first_seen"],
                    "last_seen": e["last_seen"]
                }
            else:
                edge = new_edges[ekey]
                # Merge evidence IDs and metadata
                for d_id in e["evidence_document_ids"]:
                    if d_id not in edge["evidence_document_ids"]:
                        edge["evidence_document_ids"].append(d_id)
                edge["evidence_count"] = len(edge["evidence_document_ids"])
                edge["confidence"] = max(edge["confidence"], e["confidence"])
                if e["rationale"] and e["rationale"] not in edge["rationale"]:
                    edge["rationale"] = edge["rationale"] + " | " + e["rationale"]
                if e["first_seen"] and (not edge["first_seen"] or e["first_seen"] < edge["first_seen"]):
                    edge["first_seen"] = e["first_seen"]
                if e["last_seen"] and (not edge["last_seen"] or e["last_seen"] > edge["last_seen"]):
                    edge["last_seen"] = e["last_seen"]

        final_nodes = new_nodes
        final_edges = list(new_edges.values())

    # 9. Generate Analyst Takeaway
    if entity_type == "vendor":
        related_products = sorted(list({n["label"] for n in final_nodes if n["entity_type"] == "product" and n["id"] != "selected"}))
        if related_products:
            prod_text = ", ".join(related_products[:3])
            if len(related_products) > 3:
                prod_text += " and others"
        else:
            prod_text = "various products"
        analyst_takeaway = f"Vendor {display_value} appears across CISA KEV evidence in sampled vulnerability records affecting products such as {prod_text}. Prioritize review of active exploitation trends for {display_value} software."
    elif entity_type == "product":
        related_vendors = sorted(list({n["label"] for n in final_nodes if n["entity_type"] == "vendor" and n["id"] != "selected"}))
        if related_vendors:
            vendor_text = ", ".join(related_vendors[:3])
            if len(related_vendors) > 3:
                vendor_text += " and others"
        else:
            vendor_text = "various vendors"
        analyst_takeaway = f"Product {display_value} appears across sampled CISA KEV vulnerability records associated with {vendor_text}. Prioritize patch validation for actively exploited {display_value} CVEs."
    elif entity_type == "cve":
        if is_kev:
            analyst_takeaway = (
                f"Vulnerability {display_value} is listed in CISA's Known Exploited Vulnerabilities catalog. "
                f"It affects product {kev_product or 'unknown'} by vendor {kev_vendor or 'unknown'}. "
                f"Immediate patching and remediation are highly recommended due to active in-the-wild exploitation."
            )
        else:
            analyst_takeaway = f"Vulnerability {display_value} is observed in security advisories/reports. Review affected products and patch status."
    elif entity_type == "package":
        pkg_name = display_value
        p_list = sorted(list(ghsa_packages_set))
        if p_list:
            pkg_name = ", ".join(p_list)
        analyst_takeaway = (
            f"Software package {pkg_name} is affected by software vulnerability advisory {ghsa_id or 'unknown'} "
            f"with severity level {ghsa_severity or 'unknown'}. Review application dependencies to verify if the package is in use."
        )
    elif is_platform_domain(value):
        analyst_takeaway = f"{display_value} is a CTI platform/reference domain observed in ThreatFox/abuse.ch evidence, not the malicious IOC itself."
    elif is_path_artifact(value):
        analyst_takeaway = f"{display_value} appears to be a script/path artifact extracted from malware URLs; the actual observed infrastructure is the host/IP/full URL, not {display_value} as a standalone domain."
    elif is_abused_hosting(value):
        analyst_takeaway = f"Domain {display_value} is an abused hosting platform observed in phishing campaigns; the infrastructure is shared, hosting legitimate content alongside malicious URLs."
    elif is_reference_domain(entity_type, value):
        analyst_takeaway = (
            f"Domain {display_value} is identified as a reference or software project domain in collected CTI Security Advisories. "
            f"It is not classified as malicious infrastructure."
        )
    else:
        focus_edges = [e for e in final_edges if e["source"] == "selected" or e["target"] == "selected"]
        has_observed_ioc = any(e["predicate"] == "OBSERVED_IOC" for e in focus_edges)
        has_observed_malware = any(e["predicate"] == "OBSERVED_MALWARE_URL" for e in focus_edges)
        has_observed_phish = any(e["predicate"] in ("OBSERVED_PHISHING_URL", "ABUSED_HOSTING_PLATFORM") for e in focus_edges)

        if has_observed_phish:
            analyst_takeaway = (
                f"Phishing campaign infrastructure detected targeting brand {phish_target or 'unknown'}. "
                f"Observed active phishing domains/URLs are actively used for credential theft and harvesting."
            )
        elif has_observed_ioc or has_observed_malware:
            analyst_takeaway = (
                f"Malicious infrastructure indicator of compromise associated with malware family {malware_family or 'unknown'}. "
                f"Observed threat type: {threat_type or 'malware download'}. Monitored nodes pose severe system intrusion risks."
            )
        else:
            analyst_takeaway = f"Focused entity {display_value} was observed across {len(docs)} OSINT document(s) published by {len(source_names_set)} unique source(s)."

    # 10. Create Clusters
    clusters = []
    risk_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for risk in ("critical", "high", "medium", "low", "info"):
        node_ids = [n["id"] for n in final_nodes if n["risk_level"] == risk]
        if node_ids:
            clusters.append({
                "id": f"cluster-risk-{risk}",
                "label": f"{risk.upper()} RISK GROUP",
                "node_ids": node_ids
            })

    # 11. Generate filters metadata
    filters = {
        "categories": sorted(list({e["category"] for e in final_edges})),
        "entity_types": sorted(list({n["entity_type"] for n in final_nodes if n["entity_type"]})),
        "risk_levels": sorted(list({n["risk_level"] for n in final_nodes}), key=lambda r: risk_rank[r]),
        "source_types": sorted(list(source_types_set))
    }

    caveats = sorted(list(set(caveats)))

    return {
        "summary": {
            "focus": {"type": entity_type, "value": display_value},
            "analyst_takeaway": analyst_takeaway,
            "evidence_count": total_evidence_count,
            "total_evidence_count": total_evidence_count,
            "displayed_evidence_count": displayed_evidence_count,
            "aggregation_applied": aggregation_applied,
            "relationship_count": len(final_edges),
            "source_count": len(source_names_set),
            "caveats": caveats
        },
        "nodes": final_nodes,
        "edges": final_edges,
        "triples": triples,
        "clusters": clusters,
        "filters": filters
    }
