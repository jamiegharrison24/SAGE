"""
The 10-15 "previously-flagged bad-call signatures" the task refers to were not
found anywhere in the repo or memory (same missing-artifact problem as the
design doc, minus the doc itself -- only three names survived: the /etc/shadow
one, Net User Command Response, Skype VOIP version check).

Reconstructed here by an explicit, stated rule rather than guessed: those
three, plus the 12 lowest top1-score rows in predictions.csv (method 1,
ATTACK-BERT full list, the original "just build the mapper" run), filtered to
our 773-signature ground-truth population. This list is RECONSTRUCTED, not
the original flagged list -- results.md labels it as such.
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

KNOWN_NAMES = [
    "ET WEB_SERVER /etc/shadow Detected in URI",
    "ET ATTACK_RESPONSE Net User Command Response",
    "ET CHAT Skype VOIP Checking Version (Startup)",
]


def load_gt_signatures():
    with open(os.path.join(HERE, "ground_truth_signatures.csv"), newline="", encoding="utf-8") as fh:
        return {r["signature"] for r in csv.DictReader(fh)}


def main():
    gt_sigs = load_gt_signatures()
    with open(os.path.join(HERE, "predictions.csv"), newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    labelled = [r for r in rows if r["signature"] and not r["signature"].startswith("#")
                and r["signature"] in gt_sigs]

    by_score = sorted(labelled, key=lambda r: float(r["score_1"]))
    picked = list(KNOWN_NAMES)
    for r in by_score:
        if len(picked) >= 15:
            break
        if r["signature"] not in picked:
            picked.append(r["signature"])

    out_path = os.path.join(HERE, "bad_call_signatures.txt")
    with open(out_path, "w", encoding="utf-8") as fh:
        for sig in picked:
            fh.write(sig + "\n")
    print(f"Wrote {len(picked)} reconstructed bad-call signatures to {out_path}")
    return picked


if __name__ == "__main__":
    main()
