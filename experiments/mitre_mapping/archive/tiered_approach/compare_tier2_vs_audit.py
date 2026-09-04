"""
Cross-check Tier 2 (tier2_classifier.py) predictions against the hand-audited
signature sample (hand_audit_sample*.csv) -- our small but trustworthy,
randomly-sampled, non-vendor-tag-selected ground truth, as opposed to the
bridge-table-propagated ground_truth_signatures.csv used elsewhere.

Usage: python compare_tier2_vs_audit.py
Requires tier2_predictions.csv (run tier2_classifier.py first) and the
hand_audit_sample*.csv batches in this directory.
Writes tier2_vs_audit_findings.md.
"""
import csv
import glob
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(HERE, "tier2_vs_audit_findings.md")


def parse_proposed(cell):
    """None for ambiguous/non-malicious rows (excluded from strict scoring),
    else the set of acceptable technique IDs."""
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    ids = re.findall(r"T\d{4}(?:\.\d{3})?", cell)
    return set(ids) if ids else None


def main():
    audit = {}
    for fn in sorted(glob.glob(os.path.join(HERE, "hand_audit_sample*.csv"))):
        with open(fn, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                audit[row["signature"]] = (
                    parse_proposed(row["proposed_technique"]),
                    row["proposed_technique"],
                    row["current_gt"],
                )

    preds = {}
    with open(os.path.join(HERE, "tier2_predictions.csv"), encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            preds[row["signature"]] = (row["predicted_technique_1"], row["score_1"])

    matched = scoreable = correct = t1190_count = 0
    rows_out = []
    for sig, (ids, proposed_raw, current_gt) in audit.items():
        if sig not in preds:
            continue
        matched += 1
        pred_tech, score = preds[sig]
        if pred_tech == "T1190":
            t1190_count += 1
        if ids is None:
            rows_out.append((sig, proposed_raw, current_gt, pred_tech, score, "SKIPPED"))
            continue
        scoreable += 1
        hit = pred_tech in ids
        correct += hit
        rows_out.append((sig, proposed_raw, current_gt, pred_tech, score, "HIT" if hit else "MISS"))

    lines = [
        "# Tier 2 vs. hand-audited sample\n",
        f"- matched audit rows found in tier2_predictions.csv: **{matched}**",
        f"- scoreable (non-ambiguous) rows: **{scoreable}**",
        f"- top-1 correct vs. hand-audit proposed technique: **{correct}/{scoreable} = {correct/scoreable:.1%}**",
        f"- tier2 predicted T1190 as top-1 in **{t1190_count}/{matched} = {t1190_count/matched:.1%}** of all matched rows\n",
        "## Miss rows\n",
        "| proposed | current_gt | tier2_pred (score) | signature |",
        "|---|---|---|---|",
    ]
    for sig, proposed_raw, current_gt, pred_tech, score, verdict in rows_out:
        if verdict == "MISS":
            lines.append(f"| {proposed_raw} | {current_gt} | {pred_tech} ({score}) | {sig} |")
    lines += ["\n## Hit rows\n", "| proposed | tier2_pred (score) | signature |", "|---|---|---|"]
    for sig, proposed_raw, current_gt, pred_tech, score, verdict in rows_out:
        if verdict == "HIT":
            lines.append(f"| {proposed_raw} | {pred_tech} ({score}) | {sig} |")

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {OUT_PATH}")
    print(f"top-1 vs hand-audit: {correct}/{scoreable} = {correct/scoreable:.1%}")
    print(f"T1190 top-1 rate: {t1190_count}/{matched} = {t1190_count/matched:.1%}")


if __name__ == "__main__":
    main()
