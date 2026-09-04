import csv
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_PATH = os.path.join(HERE, "et_labeled_corpus.csv")

with open(CORPUS_PATH, encoding="utf-8") as fh:
    rows = list(csv.DictReader(fh))
print("total rows:", len(rows))

tech_counter = Counter()
tactic_counter = Counter()
for r in rows:
    for t in r["technique_ids"].split(";"):
        if t:
            tech_counter[t] += 1
    for t in r["tactic_ids"].split(";"):
        if t:
            tactic_counter[t] += 1

print("distinct techniques:", len(tech_counter))
for min_sup in (2, 3, 5, 10, 20):
    n = sum(1 for c in tech_counter.values() if c >= min_sup)
    print(f"  techniques with >= {min_sup} examples: {n}")

print("distinct tactics:", len(tactic_counter))
print(tactic_counter.most_common())

rows_with_tech = sum(1 for r in rows if r["technique_ids"])
rows_with_tactic_only = sum(1 for r in rows if not r["technique_ids"] and r["tactic_ids"])
print("rows with >=1 technique id:", rows_with_tech)
print("rows with tactic-only (no technique):", rows_with_tactic_only)
