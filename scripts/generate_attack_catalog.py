import json
import urllib.request
from pathlib import Path

TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

def generate_catalog():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    print(f"Downloading Enterprise ATT&CK dataset from {url}...")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req) as response:
        stix_data = json.loads(response.read().decode("utf-8"))

    catalog = {}
    objects = stix_data.get("objects", [])
    print(f"Parsing {len(objects)} STIX objects...")

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Find technique_id
        technique_id = None
        url_ref = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url_ref = ref.get("url")
                break

        if not technique_id:
            continue

        # Extract tactics
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                pretty_tactic = TACTIC_MAP.get(phase_name, phase_name.replace("-", " ").title())
                if pretty_tactic not in tactics:
                    tactics.append(pretty_tactic)

        # Let's save it. If the key already exists, merge tactics or keep the unrevoked/newer one.
        # But generally technique_id is unique per active/revoked pair.
        catalog[technique_id.upper()] = {
            "technique_id": technique_id,
            "name": obj.get("name"),
            "tactics": tactics,
            "description": obj.get("description", ""),
            "url": url_ref
        }

    output_path = Path("data/attack_enterprise_techniques.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)

    print(f"Successfully generated {len(catalog)} enterprise techniques and saved to {output_path}")

if __name__ == "__main__":
    generate_catalog()
