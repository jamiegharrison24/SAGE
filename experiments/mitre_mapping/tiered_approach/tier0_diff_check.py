import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
TIER0_HITS_PATH = os.path.join(HERE, "tier0_hits.csv")

gt = {}
with open(GT_PATH, encoding="utf-8") as fh:
    for row in csv.DictReader(fh):
        gt[row["signature"]] = row

with open(TIER0_HITS_PATH, encoding="utf-8") as fh:
    hits = list(csv.DictReader(fh))

print(f"{'signature':70s} | GT (stage->ids) | ET-metadata")
for h in hits[:30]:
    sig = h["signature"]
    g = gt.get(sig, {})
    gt_str = f"{g.get('micro_attack_stage')}->{g.get('gt_ids')}"
    et_str = f"{h['technique_ids']} / tactics={h['tactic_ids']}"
    print(f"{sig[:70]:70s} | {gt_str:35s} | {et_str}")
