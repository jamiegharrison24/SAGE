"""
Phase 1 step 2: validate every technique/tactic ID in bridge_table.py against
the live official ATT&CK STIX data (experiments/mitre_mapping/enterprise-attack.json).
Flags/fixes anything that doesn't resolve, and resolves the one sub-technique
range (SPEARPHISHING: T1566.001-T1566.003) to concrete IDs.

Writes bridge_table_validated.json: {stage_name: {kind, resolved_ids, confidence, note}}
"""
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bridge_table import BRIDGE_TABLE  # noqa: E402
import attack_data  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    objs = attack_data.load_bundle()
    techniques = attack_data.load_techniques(objs)  # id -> object, non-deprecated/revoked
    tactics_by_shortname = attack_data.load_tactics(objs)
    valid_tactic_ids = set(tactics_by_shortname.values())

    print(f"Live corpus: {len(techniques)} non-deprecated/non-revoked techniques, "
          f"{len(valid_tactic_ids)} tactics")

    problems = []
    resolved = {}

    for stage, row in BRIDGE_TABLE.items():
        kind = row["kind"]
        entry = {"kind": kind, "confidence": row["confidence"], "note": row["note"], "resolved_ids": []}

        if kind == "none":
            resolved[stage.name] = entry
            continue

        if "range" in row and row["range"]:
            start_id, end_id = row["range"]
            expanded = attack_data.expand_range(start_id, end_id, techniques)
            if not expanded:
                problems.append(f"{stage.name}: range {start_id}-{end_id} resolved to NOTHING in live corpus")
            entry["resolved_ids"] = expanded
            resolved[stage.name] = entry
            continue

        ids = row["ids"]
        good_ids = []
        for tid in ids:
            if kind == "technique":
                if tid in techniques:
                    good_ids.append(tid)
                else:
                    problems.append(f"{stage.name}: technique ID {tid} NOT FOUND in live corpus (drafted from memory)")
            elif kind == "tactic":
                if tid in valid_tactic_ids:
                    good_ids.append(tid)
                else:
                    problems.append(f"{stage.name}: tactic ID {tid} NOT FOUND in live corpus")
        entry["resolved_ids"] = good_ids
        resolved[stage.name] = entry

    print(f"\n{len(problems)} validation problems:")
    for p in problems:
        print(f"  ! {p}")
    if not problems:
        print("  (none -- every ID in the design doc's draft table resolved against live STIX data)")

    out_path = os.path.join(HERE, "bridge_table_validated.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(resolved, fh, indent=2)
    print(f"\nWrote validated bridge table to {out_path}")

    return resolved, problems


if __name__ == "__main__":
    main()
