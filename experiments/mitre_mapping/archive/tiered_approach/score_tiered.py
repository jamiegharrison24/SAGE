"""
Score the tiered pipeline the same way ../score.py scores methods 1-7, PLUS
break results down per-tier (the "coverage-at-precision" view the tiered
strategy asks for: what fraction is auto-mappable, and at what precision,
tier by tier).

Usage: python score_tiered.py
"""
import csv
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import score as base_score  # noqa: E402

GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
PRED_PATH = os.path.join(HERE, "predictions_tiered.csv")
PROVENANCE_PATH = os.path.join(HERE, "provenance.csv")
OUT_JSON = os.path.join(HERE, "tiered_scores.json")


def load_provenance():
    with open(PROVENANCE_PATH, encoding="utf-8") as fh:
        return {row["signature"]: row["resolved_by_tier"] for row in csv.DictReader(fh)}


def main():
    gt = base_score.load_ground_truth()
    tid_to_tactics = base_score.build_tactic_index()
    provenance = load_provenance()

    overall = base_score.score_method("tiered", PRED_PATH, gt, tid_to_tactics)
    print("=== OVERALL (all tiers combined) ===")
    print(json.dumps(overall, indent=2, default=str))

    preds = base_score.load_predictions(PRED_PATH, gt)

    per_tier = {}
    for tier in ("tier0", "tier1", "tier2", "tier3"):
        sigs_in_tier = {s for s, t in provenance.items() if t == tier}
        n = 0
        top1_hits = 0
        top1_lenient = 0
        right_tactic = 0
        n_technique_scoreable = 0
        n_tactic_only = 0
        n_unmappable = 0
        for sig in sigs_in_tier:
            row = gt.get(sig)
            if row is None or sig not in preds or not preds[sig]:
                continue
            if row["gt_kind"] == "unmappable":
                n_unmappable += 1
                continue
            if row["gt_kind"] == "tactic_only":
                n_tactic_only += 1
            else:
                n_technique_scoreable += 1
            gt_ids = set(row["gt_ids"].split(";")) if row["gt_ids"] else set()
            gtt = base_score.gt_tactics(row, tid_to_tactics)
            pred1_tid, _ = preds[sig][0]
            n += 1
            if base_score.strict_match(pred1_tid, gt_ids):
                top1_hits += 1
            if base_score.lenient_match(pred1_tid, gt_ids):
                top1_lenient += 1
            if tid_to_tactics.get(pred1_tid, set()) & gtt:
                right_tactic += 1
        per_tier[tier] = {
            "n_signatures": len(sigs_in_tier),
            "n_technique_scoreable": n_technique_scoreable,
            "n_tactic_only": n_tactic_only,
            "n_unmappable_excluded": n_unmappable,
            "n_scored": n,
            "top1_acc": top1_hits / n if n else None,
            "top1_acc_lenient_subtechnique": top1_lenient / n if n else None,
            "right_tactic_rate": right_tactic / n if n else None,
        }

    print("\n=== PER-TIER (coverage-at-precision) ===")
    print(json.dumps(per_tier, indent=2, default=str))

    n_abstain = sum(1 for t in provenance.values() if t == "tier4_abstain")
    coverage_summary = {
        "n_total_signatures": len(gt),
        "n_covered": len(gt) - n_abstain,
        "n_abstained_tier4": n_abstain,
        "coverage_pct": (len(gt) - n_abstain) / len(gt) * 100,
    }
    print("\n=== COVERAGE ===")
    print(json.dumps(coverage_summary, indent=2))

    out = {"overall": overall, "per_tier": per_tier, "coverage": coverage_summary}
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)
    print(f"\nWrote {OUT_JSON}")


if __name__ == "__main__":
    main()
