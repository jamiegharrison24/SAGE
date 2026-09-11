"""
Measure what the Step 1 gazetteer actually covers on the 397 scoreable eval
rows, and dump a sample for hand-checking precision.

Reports three numbers, per `../../entity_normalisation_plan.md` §5 Step 1,
because a bare match count over a 94k-entry list would lie:
  1. rows matched at all
  2. rows matched, by entity type and source
  3. a sample of matches for manual precision review

Not gated by Step 0 -- this is coverage counting, not accuracy evaluation, so
the `reviewer_verdict` question does not contaminate it.

Usage: python measure_coverage.py [--sample N] [--seed N]
"""
import argparse
import csv
import glob
import os
import random
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, ".."))
DATA = os.path.join(PKG, "data")
GAZ_PATH = os.path.join(DATA, "entity_gazetteer.csv")

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")


def parse_proposed(cell):
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", cell)) or None


def load_eval_rows():
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA, "hand_audit_sample*.csv"))):
        rows += list(csv.DictReader(open(fn, encoding="utf-8")))
    p = os.path.join(DATA, "labeled_set_v2.csv")
    if os.path.exists(p):
        rows += list(csv.DictReader(open(p, encoding="utf-8")))
    return rows


def load_gazetteer(exclude_sources=()):
    """Returns (single_token_index, multiword_index).

    CPE spells multi-word products with underscores (`bb_flashback`), which no
    signature title contains, so those are indexed by their space form too.
    """
    single, multi = {}, {}
    with open(GAZ_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name, etype, source = row["name"], row["type"], row["source"]
            if source in exclude_sources:
                continue
            spaced = name.replace("_", " ").replace("-", " ").strip()
            if " " in spaced:
                multi[spaced] = (etype, source)
            else:
                single[name] = (etype, source)
    return single, multi


def match(title, single, multi, max_ngram=4):
    """Returns list of (matched_text, type, source).

    N-grams are generated from the *title* and looked up in the multi-word
    index, rather than testing all ~30k multi-word entries against each title
    -- the latter is 12M regex searches over the eval set and does not finish.
    """
    low = title.lower()
    toks = _TOKEN_RE.findall(low)
    found = []

    for size in range(max_ngram, 1, -1):
        for i in range(len(toks) - size + 1):
            phrase = " ".join(toks[i:i + size])
            hit = multi.get(phrase)
            if hit:
                found.append((phrase, hit[0], hit[1]))

    for tok in set(toks):
        hit = single.get(tok) or single.get(tok.rstrip(".-_"))
        if hit:
            found.append((tok, hit[0], hit[1]))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--exclude-source", action="append", default=[],
                    help="drop a source, e.g. --exclude-source cpedict")
    args = ap.parse_args()

    if not os.path.exists(GAZ_PATH):
        raise SystemExit(f"{GAZ_PATH} not found -- run build_dicts.py first")

    single, multi = load_gazetteer(tuple(args.exclude_source))
    print(f"gazetteer: {len(single)} single-token + {len(multi)} multi-word entries\n")

    rows = load_eval_rows()
    scoreable = [r for r in rows if parse_proposed(r["proposed_technique"]) is not None]

    matched_rows = 0
    by_type_rows = defaultdict(int)
    by_source_rows = defaultdict(int)
    all_matches = []
    token_freq = Counter()

    for r in scoreable:
        sig = r["signature"]
        hits = match(sig, single, multi)
        if hits:
            matched_rows += 1
            for t in {h[1] for h in hits}:
                by_type_rows[t] += 1
            for s in {h[2] for h in hits}:
                by_source_rows[s] += 1
            for h in hits:
                all_matches.append((sig, h[0], h[1], h[2]))
                token_freq[h[0]] += 1

    n = len(scoreable)
    print(f"scoreable rows: {n}")
    print(f"rows with >=1 gazetteer match: {matched_rows} ({matched_rows / n:.1%})\n")

    print("rows matched, by entity type:")
    for t, c in sorted(by_type_rows.items(), key=lambda kv: -kv[1]):
        print(f"   {t:10s} {c:4d}  ({c / n:.1%})")
    print("\nrows matched, by source:")
    for s, c in sorted(by_source_rows.items(), key=lambda kv: -kv[1]):
        print(f"   {s:12s} {c:4d}  ({c / n:.1%})")

    print(f"\ntotal matches: {len(all_matches)}  distinct matched strings: {len(token_freq)}")
    print("\nmost frequently matched strings (inspect for noise):")
    for tok, c in token_freq.most_common(25):
        etype = next(m[2] for m in all_matches if m[1] == tok)
        print(f"   {tok:22s} x{c:<4d} [{etype}]")

    random.seed(args.seed)
    sample = random.sample(all_matches, min(args.sample, len(all_matches)))
    out = os.path.join(HERE, "coverage_sample.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "matched_text", "type", "source", "verdict"])
        for m in sample:
            w.writerow([*m, ""])
    print(f"\nwrote {len(sample)}-match sample for hand review -> {out}")
    print("\n--- sample ---")
    for sig, tok, etype, source in sample:
        print(f"  [{etype:8s}] {tok:20s} <- {sig[:66]}")


if __name__ == "__main__":
    sys.exit(main())
