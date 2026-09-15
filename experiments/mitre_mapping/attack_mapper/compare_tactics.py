"""Compare sentence-transformer and manual labels at ATT&CK tactic level."""

import csv
import json
import os
import re


HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(HERE, "data", "compare.csv")
OUTPUT_PATH = os.path.join(HERE, "data", "compare_tactics.csv")
BUNDLE_PATH = os.path.join(os.path.dirname(HERE), "enterprise-attack.json")
CODE_PATTERN = re.compile(r"TA\d+|T\d+(?:\.\d+)?")


def external_id(obj):
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def load_tactics():
    with open(BUNDLE_PATH, encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]

    tactic_ids = {
        obj.get("x_mitre_shortname"): external_id(obj)
        for obj in objects
        if obj.get("type") == "x-mitre-tactic" and external_id(obj)
    }
    technique_tactics = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = external_id(obj)
        if not technique_id:
            continue
        technique_tactics[technique_id] = {
            tactic_ids[phase["phase_name"]]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name") in tactic_ids
        }
    return technique_tactics


def codes_to_tactics(value, technique_tactics):
    tactics = set()
    for code in CODE_PATTERN.findall(value or ""):
        if code.startswith("TA"):
            tactics.add(code)
        else:
            tactics.update(technique_tactics.get(code, set()))
    return sorted(tactics)


def main():
    technique_tactics = load_tactics()
    with open(INPUT_PATH, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))

    fieldnames = [
        "alert",
        "sentence transformer said",
        "manual verification said",
        "sentence transformer tactic(s)",
        "manual verification tactic(s)",
        "match?",
    ]
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            sentence_tactics = codes_to_tactics(
                row["sentence transformer said"], technique_tactics
            )
            manual_tactics = codes_to_tactics(
                row["manual verification said"], technique_tactics
            )
            writer.writerow(
                {
                    "alert": row["alert"],
                    "sentence transformer said": row["sentence transformer said"],
                    "manual verification said": row["manual verification said"],
                    "sentence transformer tactic(s)": ";".join(sentence_tactics),
                    "manual verification tactic(s)": ";".join(manual_tactics),
                    "match?": "T" if set(sentence_tactics) & set(manual_tactics) else "F",
                }
            )

    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()