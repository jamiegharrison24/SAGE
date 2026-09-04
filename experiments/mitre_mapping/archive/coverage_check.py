"""
Standalone coverage check: how many distinct Suricata `alert.signature` strings
in the raw alert corpora (cptc-2017, cptc-2018, ccdc) are already covered by
the hardcoded signature->MicroAttackStage dictionaries in
signatures/alert_signatures.py, and how many are not (and therefore silently
default to NON_MALICIOUS via alert_loading._get_attack_stage_mapping).

Does not touch the production pipeline. Reads raw alert JSON directly.

Usage: python3 experiments/mitre_mapping/coverage_check.py
"""
import glob
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

import signatures.alert_signatures as sig_module  # noqa: E402

DATASETS = {
    "cptc-2017": os.path.join(REPO_ROOT, "alerts", "cptc-2017"),
    "cptc-2018": os.path.join(REPO_ROOT, "alerts", "cptc-2018"),
    "ccdc": os.path.join(REPO_ROOT, "alerts", "ccdc"),
}

OUTPUT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "predictions.csv")


def hardcoded_signatures():
    """Union of every string key/entry across all signature containers in
    signatures/alert_signatures.py (dicts and lists), excluding
    attack_stage_mapping whose keys are MicroAttackStage enums, not strings."""
    all_sigs = set()
    for name in dir(sig_module):
        if name.startswith("_") or name == "attack_stage_mapping":
            continue
        value = getattr(sig_module, name)
        if isinstance(value, dict):
            all_sigs |= {k for k in value.keys() if isinstance(k, str)}
        elif isinstance(value, list):
            all_sigs |= {x for x in value if isinstance(x, str)}
    return all_sigs


def extract_signature(raw_event):
    if "result" in raw_event and "_raw" in raw_event["result"]:
        raw = json.loads(raw_event["result"]["_raw"])
    elif "_raw" in raw_event:
        raw = json.loads(raw_event["_raw"])
    else:
        raw = raw_event

    if raw.get("event_type") != "alert":
        return None
    return raw["alert"]["signature"]


def signatures_in_dataset(dataset_dir):
    sigs = set()
    json_files = [
        f for f in glob.glob(os.path.join(dataset_dir, "*.json"))
    ]
    for path in json_files:
        with open(path, "r") as fh:
            data = json.load(fh)
        for event in data:
            sig = extract_signature(event)
            if sig is not None:
                sigs.add(sig)
    return sigs


def main():
    hardcoded = hardcoded_signatures()
    print(f"Hardcoded signatures across signatures/alert_signatures.py: {len(hardcoded)}")

    per_dataset = {}
    combined = set()
    for name, path in DATASETS.items():
        sigs = signatures_in_dataset(path)
        per_dataset[name] = sigs
        combined |= sigs

    rows = []
    header = f"{'dataset':<12}{'distinct_sigs':>15}{'covered':>10}{'uncovered':>12}"
    print(header)
    print("-" * len(header))
    for name, sigs in per_dataset.items():
        covered = sigs & hardcoded
        uncovered = sigs - hardcoded
        rows.append((name, len(sigs), len(covered), len(uncovered)))
        print(f"{name:<12}{len(sigs):>15}{len(covered):>10}{len(uncovered):>12}")

    covered = combined & hardcoded
    uncovered = combined - hardcoded
    rows.append(("combined", len(combined), len(covered), len(uncovered)))
    print(f"{'combined':<12}{len(combined):>15}{len(covered):>10}{len(uncovered):>12}")

    uncovered_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uncovered_signatures.txt")
    with open(uncovered_path, "w") as fh:
        for sig in sorted(uncovered):
            fh.write(sig + "\n")
    print(f"\nWrote {len(uncovered)} uncovered signatures to {uncovered_path}")

    return rows, per_dataset, hardcoded


if __name__ == "__main__":
    main()
