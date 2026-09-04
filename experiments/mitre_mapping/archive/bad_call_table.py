"""Builds the reconstructed bad-call-signature x method comparison table (top-1
prediction only) for results.md."""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from score import METHOD_FILES, load_predictions  # noqa: E402
from ground_truth import merge_with_conflicts  # noqa: E402


def main():
    with open(os.path.join(HERE, "bad_call_signatures.txt"), encoding="utf-8") as fh:
        sigs = [l.strip() for l in fh if l.strip()]

    gt_rows = {}
    with open(os.path.join(HERE, "ground_truth_signatures.csv"), newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            gt_rows[r["signature"]] = r

    all_preds = {}
    for name, path in METHOD_FILES.items():
        all_preds[name] = load_predictions(path, gt_rows)

    print("| signature | GT (stage -> ids) | " + " | ".join(METHOD_FILES.keys()) + " |")
    print("|---|---|" + "---|" * len(METHOD_FILES))
    for sig in sigs:
        gt = gt_rows.get(sig)
        gt_str = f"{gt['micro_attack_stage']} -> {gt['gt_ids'] or '(none)'}" if gt else "?"
        cells = []
        for name in METHOD_FILES:
            preds = all_preds[name].get(sig)
            cells.append(preds[0][0] if preds else "-")
        print(f"| {sig} | {gt_str} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
