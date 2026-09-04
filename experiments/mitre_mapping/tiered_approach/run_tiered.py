"""
Orchestrator: combine tiers in priority order into one prediction per
signature, score.py-compatible.

  Tier 0 (exact ET rule-metadata match)      -- highest priority, ~100% precision
  Tier 1 (STIX malware/tool alias match)     -- high precision, narrow coverage
  Tier 2 (classifier, accepted only if confident: top decision score > 0)
  Tier 3 (TF-IDF similarity fallback, accepted only if cosine score >= ABSTAIN_FLOOR)
  Tier 4 (abstain -- no row written to predictions_tiered.csv; listed in
          unmapped.csv with its Tier-3 top-5 candidates for human review)

Usage: python run_tiered.py
Requires tier0_hits.csv, tier1_hits.csv, tier2_predictions.csv,
tier3_predictions.csv already built (run tier0_build.py, tier1_build.py,
tier2_classifier.py, tier3_similarity.py first).
"""
import csv
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")

TIER0_PATH = os.path.join(HERE, "tier0_hits.csv")
TIER1_PATH = os.path.join(HERE, "tier1_hits.csv")
TIER2_PATH = os.path.join(HERE, "tier2_predictions.csv")
TIER3_PATH = os.path.join(HERE, "tier3_predictions.csv")

PRED_OUT = os.path.join(HERE, "predictions_tiered.csv")
UNMAPPED_OUT = os.path.join(HERE, "unmapped.csv")
PROVENANCE_OUT = os.path.join(HERE, "provenance.csv")

TIER2_CONFIDENCE_FLOOR = 0.0   # LinearSVC decision score: > 0 means "in-class"
TIER3_ABSTAIN_FLOOR = 0.05     # cosine similarity below this -> Tier 4 abstain


def load_tier0():
    out = {}
    with open(TIER0_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            techs = row["technique_ids"].split(";") if row["technique_ids"] else []
            if techs:
                out[row["signature"]] = techs[:3]
    return out


def load_tier1():
    out = {}
    with open(TIER1_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            techs = sorted(row["technique_ids"].split(";")) if row["technique_ids"] else []
            if techs:
                out[row["signature"]] = techs[:3]
    return out


def load_tier2():
    out = {}
    with open(TIER2_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            entries = []
            for i in (1, 2, 3):
                tid = row[f"predicted_technique_{i}"]
                score = row[f"score_{i}"]
                if tid:
                    entries.append((tid, float(score)))
            out[row["signature"]] = entries
    return out


def load_tier3():
    out = {}
    with open(TIER3_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            entries = []
            for i in (1, 2, 3, 4, 5):
                tid = row[f"predicted_technique_{i}"]
                score = row[f"score_{i}"]
                if tid:
                    entries.append((tid, float(score)))
            out[row["signature"]] = entries
    return out


def main():
    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]

    tier0 = load_tier0()
    tier1 = load_tier1()
    tier2 = load_tier2()
    tier3 = load_tier3()

    provenance = Counter()
    pred_rows = []
    unmapped_rows = []

    for sig in sigs:
        if sig in tier0:
            techs = tier0[sig]
            pred_rows.append((sig, techs, "tier0"))
            provenance["tier0"] += 1
            continue

        if sig in tier1:
            techs = tier1[sig]
            pred_rows.append((sig, techs, "tier1"))
            provenance["tier1"] += 1
            continue

        t2 = tier2.get(sig, [])
        if t2 and t2[0][1] > TIER2_CONFIDENCE_FLOOR:
            techs = [tid for tid, _ in t2]
            pred_rows.append((sig, techs, "tier2"))
            provenance["tier2"] += 1
            continue

        t3 = tier3.get(sig, [])
        if t3 and t3[0][1] >= TIER3_ABSTAIN_FLOOR:
            techs = [tid for tid, _ in t3[:3]]
            pred_rows.append((sig, techs, "tier3"))
            provenance["tier3"] += 1
            continue

        provenance["tier4_abstain"] += 1
        unmapped_rows.append((sig, t3))

    with open(PRED_OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "signature",
            "predicted_technique_1", "score_1",
            "predicted_technique_2", "score_2",
            "predicted_technique_3", "score_3",
        ])
        for sig, techs, tier in pred_rows:
            cells = []
            for t in techs[:3]:
                cells += [t, ""]
            while len(cells) < 6:
                cells += ["", ""]
            w.writerow([sig] + cells)

    with open(UNMAPPED_OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "top5_candidates_tier3"])
        for sig, t3 in unmapped_rows:
            cand = ";".join(f"{tid}:{score:.3f}" for tid, score in t3[:5])
            w.writerow([sig, cand])

    with open(PROVENANCE_OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "resolved_by_tier"])
        for sig, techs, tier in pred_rows:
            w.writerow([sig, tier])
        for sig, _ in unmapped_rows:
            w.writerow([sig, "tier4_abstain"])

    print("Provenance (which tier resolved each of the 773 signatures):")
    for tier in ("tier0", "tier1", "tier2", "tier3", "tier4_abstain"):
        n = provenance[tier]
        print(f"  {tier:14s} {n:4d}  ({n / len(sigs) * 100:.1f}%)")
    print(f"\nWrote {PRED_OUT} ({len(pred_rows)} rows)")
    print(f"Wrote {UNMAPPED_OUT} ({len(unmapped_rows)} rows)")
    print(f"Wrote {PROVENANCE_OUT}")


if __name__ == "__main__":
    main()
