"""
Phase 4: score every method's predictions against the Phase 1 ground truth.

Metrics per method (over the technique_scoreable subset, the headline
denominator, AND over all 773 for comparison -- both reported):
  - top-1 accuracy (exact technique ID match; sub-technique parent does NOT
    match its child by default -- see LENIENT_SUBTECH below for the footnote)
  - top-3 accuracy (nearest-neighbor methods only; k-NN/SMET produce one
    answer)
  - right-tactic-wrong-technique rate (predicted technique's tactic set
    intersects the GT's tactic set)
Diagnostics (nearest-neighbor methods only): median/mean top-1 score, % below
0.5, hub-collapse (most frequently predicted techniques + counts).
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from statistics import mean, median

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attack_data  # noqa: E402

GT_PATH = os.path.join(HERE, "ground_truth_signatures.csv")

METHOD_FILES = {
    "1_attackbert_full": os.path.join(HERE, "predictions.csv"),
    "2_attackbert_filtered": os.path.join(HERE, "predictions_method2.csv"),
    "3_minilm_full": os.path.join(HERE, "predictions_method3.csv"),
    "4_minilm_filtered": os.path.join(HERE, "predictions_method4.csv"),
    "5_knn_attackbert": os.path.join(HERE, "predictions_method5.csv"),
    "6_knn_minilm": os.path.join(HERE, "predictions_method6.csv"),
    "7_smet": os.path.join(HERE, "predictions_method7.csv"),
}
NN_METHODS = {"1_attackbert_full", "2_attackbert_filtered", "3_minilm_full", "4_minilm_filtered"}
SINGLE_ANSWER_METHODS = {"5_knn_attackbert", "6_knn_minilm", "7_smet"}


def load_ground_truth():
    with open(GT_PATH, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return {r["signature"]: r for r in rows}


def parse_tid(cell):
    """'T1217 Browser Information Discovery' -> 'T1217'; '' -> None."""
    if not cell or not cell.strip():
        return None
    return cell.split()[0]


def load_predictions(path, gt_signatures):
    """Returns {signature: [(tid, score), ...]} filtered to exactly the GT
    population (drops the '# uncovered' section and anything outside our 773)."""
    preds = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        for row in reader:
            if not row or row[0].startswith("#"):
                break  # stop at the uncovered-section marker (method 1's predictions.csv)
            sig = row[0]
            if sig not in gt_signatures:
                continue
            entries = []
            for i in (1, 3, 5):
                tid = parse_tid(row[i])
                if tid:
                    raw_score = row[i + 1]
                    if raw_score and "/" in raw_score:
                        # k-NN vote fraction, e.g. "2/5" -- not a cosine similarity,
                        # excluded from the score-based diagnostics (median/mean/pct_below_0.5)
                        score = None
                    elif raw_score:
                        score = float(raw_score)
                    else:
                        score = None
                    entries.append((tid, score))
            preds[sig] = entries
    return preds


def build_tactic_index():
    objs = attack_data.load_bundle()
    techniques = attack_data.load_techniques(objs)
    shortname_to_taid = attack_data.load_tactics(objs)
    tid_to_tactics = {}
    for tid, ap in techniques.items():
        tid_to_tactics[tid] = set(attack_data.technique_tactics(ap, shortname_to_taid))
    return tid_to_tactics


def gt_tactics(row, tid_to_tactics):
    """Tactic set for a GT row: union of resolved technique's tactics if
    technique-scoreable, or the tactic id itself if tactic-level."""
    if row["gt_kind"] == "technique_scoreable":
        tas = set()
        for tid in row["gt_ids"].split(";"):
            tas |= tid_to_tactics.get(tid, set())
        return tas
    if row["gt_kind"] == "tactic_only":
        return set(row["gt_ids"].split(";"))
    return set()


def strict_match(pred_tid, gt_ids):
    return pred_tid in gt_ids


def parent(tid):
    return tid.split(".")[0]


def lenient_match(pred_tid, gt_ids):
    """Strict match, OR pred is the parent technique of a sub-technique GT id,
    OR GT is the parent of a sub-technique pred id. Needed for method 7
    (SMET), whose 185-label space is parent-technique-only -- it can never
    exactly match a sub-technique GT id (e.g. T1595.002) even when it
    correctly identifies the parent (T1595). Reported as a footnote metric
    for every method, not just SMET, for a like-for-like comparison."""
    if strict_match(pred_tid, gt_ids):
        return True
    pred_parent = parent(pred_tid)
    return any(pred_parent == g or pred_tid == parent(g) for g in gt_ids)


def score_method(name, path, gt, tid_to_tactics):
    is_nn = name in NN_METHODS
    is_single_answer = name in SINGLE_ANSWER_METHODS
    preds = load_predictions(path, gt)

    scoreable = {sig: r for sig, r in gt.items() if r["gt_kind"] == "technique_scoreable"}
    tactic_only = {sig: r for sig, r in gt.items() if r["gt_kind"] == "tactic_only"}

    def compute(pop, label):
        n = 0
        top1_hits = 0
        top1_hits_lenient = 0
        top3_hits = 0
        right_tactic = 0
        top1_scores = []
        top1_pred_counter = Counter()
        n_missing_pred = 0

        for sig, row in pop.items():
            if sig not in preds or not preds[sig]:
                n_missing_pred += 1
                continue
            n += 1
            gt_ids = set(row["gt_ids"].split(";")) if row["gt_ids"] else set()
            gtt = gt_tactics(row, tid_to_tactics)

            entries = preds[sig]
            pred1_tid, pred1_score = entries[0]
            top1_pred_counter[pred1_tid] += 1
            if pred1_score is not None:
                top1_scores.append(pred1_score)

            if strict_match(pred1_tid, gt_ids):
                top1_hits += 1
            if lenient_match(pred1_tid, gt_ids):
                top1_hits_lenient += 1
            if any(strict_match(tid, gt_ids) for tid, _ in entries[:3]):
                top3_hits += 1
            if tid_to_tactics.get(pred1_tid, set()) & gtt:
                right_tactic += 1

        return {
            "n_scored": n,
            "n_missing_pred": n_missing_pred,
            "top1_acc": top1_hits / n if n else None,
            "top1_acc_lenient_subtechnique": top1_hits_lenient / n if n else None,
            "top3_acc": (top3_hits / n if n else None) if not is_single_answer else None,
            "right_tactic_rate": right_tactic / n if n else None,
            "median_top1_score": median(top1_scores) if top1_scores else None,
            "mean_top1_score": mean(top1_scores) if top1_scores else None,
            "pct_below_0.5": (sum(1 for s in top1_scores if s < 0.5) / len(top1_scores)
                               if top1_scores else None),
            "top_hub_predictions": top1_pred_counter.most_common(5),
        }

    return {
        "technique_scoreable": compute(scoreable, "technique_scoreable"),
        "all_773": compute(gt, "all_773"),
        "n_technique_scoreable": len(scoreable),
        "n_tactic_only": len(tactic_only),
        "n_unmappable": len(gt) - len(scoreable) - len(tactic_only),
    }


def main():
    gt = load_ground_truth()
    tid_to_tactics = build_tactic_index()

    results = {}
    for name, path in METHOD_FILES.items():
        if not os.path.exists(path):
            print(f"SKIP {name}: {path} not found")
            continue
        results[name] = score_method(name, path, gt, tid_to_tactics)
        print(f"\n=== {name} ===")
        print(json.dumps(results[name], indent=2, default=str))

    out_path = os.path.join(HERE, "scores.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    print(f"\nWrote {out_path}")
    return results


if __name__ == "__main__":
    main()
