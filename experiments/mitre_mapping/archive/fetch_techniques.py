"""
Downloads the official MITRE ATT&CK Enterprise STIX data and extracts the
full technique list (including sub-techniques): ATT&CK ID, name, description.
No hardcoded technique list -- this is the fixed reference set embedded by
embed_predictions.py.

Usage: python3 experiments/mitre_mapping/fetch_techniques.py
"""
import json
import os
import urllib.request

from mitreattack.stix20 import MitreAttackData

HERE = os.path.dirname(os.path.abspath(__file__))
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX_CACHE = os.path.join(HERE, "enterprise-attack.json")
TECHNIQUES_OUT = os.path.join(HERE, "techniques.json")


def download_stix(force=False):
    if force or not os.path.exists(STIX_CACHE):
        print(f"Downloading {STIX_URL} ...")
        urllib.request.urlretrieve(STIX_URL, STIX_CACHE)
    return STIX_CACHE


def extract_techniques(stix_path):
    attack_data = MitreAttackData(stix_path)
    techniques = attack_data.get_techniques(include_subtechniques=True, remove_revoked_deprecated=True)

    rows = []
    for tech in techniques:
        external_id = None
        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break
        if external_id is None:
            continue
        rows.append({
            "technique_id": external_id,
            "name": tech.get("name", ""),
            "description": tech.get("description", ""),
        })

    rows.sort(key=lambda r: r["technique_id"])
    return rows


def main():
    stix_path = download_stix()
    rows = extract_techniques(stix_path)
    with open(TECHNIQUES_OUT, "w") as fh:
        json.dump(rows, fh, indent=2)
    print(f"Extracted {len(rows)} techniques (incl. sub-techniques) -> {TECHNIQUES_OUT}")


if __name__ == "__main__":
    main()
