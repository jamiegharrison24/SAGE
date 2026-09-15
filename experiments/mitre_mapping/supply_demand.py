"""
The shopping list for §8 lever 1: which techniques the eval set asks about, and
how many training examples exist for each.

Effort 14 established that accuracy tracks training-example count, not text
quality (`corpus_coverage_findings.md`), and gave three headline rows
(`T1595.002` 44 eval / 8 corpus, `T1499` 32/9, `T1498` 12/10). This generates
the *whole* table, per corpus, so a candidate corpus can be judged on whether
it supplies the techniques actually in demand rather than on how many distinct
techniques it happens to carry.

That distinction is the point. Sigma carries 398 techniques and Elastic 444,
against ET's 45 -- and §6.3 found diversity does not predict usefulness,
because those techniques are in the wrong register (Windows/host, cloud/
endpoint) for a network-IDS eval set. So "distinct techniques" is the wrong
statistic to shop on. **Demand-weighted coverage** is the right one: of the
eval set's rows, what share asks about a technique this corpus actually
carries, and how deeply.

Ground truth and scoreability follow `validate.py` exactly -- `proposed_technique`
parsed for technique IDs, tactic-only rows dropped, and `reviewer_verdict == "0"`
rows excluded entirely (the Step 0 rule in `label_queue/CONVENTION.md`). If this
drifts from `validate.py` the numbers stop being comparable to the headline.

Usage:
    python supply_demand.py                  # the demand table
    python supply_demand.py --csv out.csv    # also write it for a spreadsheet
"""
import argparse
import csv
import glob
import os
import re
import sys
from collections import Counter, defaultdict

from attack_mapper.corpora import CORPUS_PATHS, corpus_name

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "attack_mapper", "data")

csv.field_size_limit(10 * 1024 * 1024)

# Splunk is built but not loaded (corpora.py). Included here as a column
# because the question "would adopting it help?" is exactly a supply question,
# and answering it needs its supply counted even while it is switched off.
ALL_CORPORA = tuple(CORPUS_PATHS) + (
    os.path.join(DATA, "splunk_labeled_corpus.csv"),
)


def parse_proposed(cell):
    """Verbatim in behaviour from `validate.py:parse_proposed`."""
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", cell)) or None


def eval_rows():
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA, "hand_audit_sample*.csv"))):
        rows += list(csv.DictReader(open(fn, encoding="utf-8")))
    p = os.path.join(DATA, "labeled_set_v2.csv")
    if os.path.exists(p):
        rows += list(csv.DictReader(open(p, encoding="utf-8")))

    scoreable = []
    for r in rows:
        # Step 0: a reviewer-rejected row has no machine-readable corrected
        # label, so it is excluded rather than re-scored.
        if (r.get("reviewer_verdict") or "").strip() == "0":
            continue
        if r["proposed_technique"].strip().startswith("TA"):
            continue        # tactic-only
        ids = parse_proposed(r["proposed_technique"])
        if ids:
            scoreable.append((r, ids))
    return rows, scoreable


def corpus_supply():
    """technique -> {corpus: row count}, plus per-corpus totals."""
    supply = defaultdict(Counter)
    totals = Counter()
    for path in ALL_CORPORA:
        if not os.path.exists(path):
            continue
        name = corpus_name(path)
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                ids = [t for t in row["technique_ids"].split(";") if t]
                if not ids:
                    continue
                totals[name] += 1
                for t in set(ids):
                    supply[t][name] += 1
    return supply, totals


# The rule namespaces the pipeline knows about, from `normalize.VENDOR_PREFIXES`.
# Which *ruleset family* an eval row comes from decides which corpus could
# possibly supply it -- §6.3's "register match beats diversity" applied at the
# level of the ruleset rather than the platform.
VENDOR_FAMILY = (
    ("ET", ("ET ", "ETPRO")),
    ("Snort/Talos", ("GPL ", "MALWARE-CNC", "SERVER-", "BROWSER-", "FILE-",
                     "POLICY-", "INDICATOR-", "OS-", "PROTOCOL-", "APP-DETECT",
                     "EXPLOIT-KIT", "SQL ", "NETBIOS ", "DOS ", "SCAN ")),
    ("Suricata built-in", ("SURICATA",)),
)


def vendor_family(sig):
    up = sig.upper()
    for name, prefixes in VENDOR_FAMILY:
        if any(up.startswith(p.upper()) for p in prefixes):
            return name
    return "(other)"


def vendor_breakdown(scoreable):
    """Which ruleset family does the eval set actually draw on?

    The corpora are ET + Sigma + Elastic. There is **no Snort corpus**, yet
    `normalize.VENDOR_PREFIXES` enumerates a dozen Snort/Talos namespaces
    because the eval set contains them. If a material share of demand is
    Snort-family, "a corpus in the right register" has a specific named
    answer rather than needing a survey.
    """
    fam = Counter(vendor_family(r["signature"]) for r, _ids in scoreable)
    n = sum(fam.values())
    print("\n" + "=" * 61)
    print("Eval rows by ruleset family -- which corpus could supply them")
    print("=" * 61)
    print(f"  {'family':>20} {'rows':>6} {'share':>8}  corpus on disk")
    have = {"ET": "yes (26,644 rows)", "Snort/Talos": "**NONE**",
            "Suricata built-in": "**NONE**", "(other)": "-"}
    for name, c in fam.most_common():
        print(f"  {name:>20} {c:>6} {c / n:>7.1%}  {have.get(name, '-')}")


def parse_validation_report(path):
    """(expected_ids, verdict) per scored row from a generated report table."""
    out = []
    if not os.path.exists(path):
        return out
    row_re = re.compile(r"^\|\s*([^|]+?)\s*\|[^|]*\|\s*(HIT|MISS|SKIPPED)\s*\|")
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = row_re.match(line)
            if not m:
                continue
            ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", m.group(1)))
            if ids and m.group(2) in ("HIT", "MISS"):
                out.append((ids, m.group(2)))
    return out


def supply_gradient(supply, loaded, demand):
    """Does accuracy actually track *training-example* count?

    `corpus_coverage_findings.md` buckets by **eval** frequency -- its header
    says so and the counts reconcile exactly (189/3, 137/21, 35/27). REPORT.md
    transcribes the same table as "corpus examples of the true technique",
    which is a different and much stronger claim. This computes the version
    REPORT.md describes, off the generated per-row results, so the two can be
    told apart.
    """
    rows = parse_validation_report(os.path.join(HERE, "validation_report.md"))
    if not rows:
        print("\n(validation_report.md absent -- skipping the supply gradient)")
        return
    print("\n" + "=" * 61)
    print("Accuracy by SUPPLY bucket -- testing REPORT.md's stated claim")
    print("=" * 61)

    def sup(ids):
        return max(sum(supply[t][n] for n in loaded) for t in ids)

    def dem(ids):
        return max(demand[t] for t in ids)

    for label, key in (("corpus supply", sup), ("eval frequency", dem)):
        print(f"\n  bucketed by {label}:")
        print(f"    {'bucket':>14} {'rows':>6} {'hits':>6} {'top-1':>8}")
        for name, lo, hi in (("head (>=20)", 20, None), ("mid (3-19)", 3, 19),
                             ("tail (<=2)", None, 2)):
            sel = [v for ids, v in rows
                   if (lo is None or key(ids) >= lo)
                   and (hi is None or key(ids) <= hi)]
            if not sel:
                continue
            hits = sum(1 for v in sel if v == "HIT")
            print(f"    {name:>14} {len(sel):>6} {hits:>6} "
                  f"{hits / len(sel):>7.1%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="also write the table here")
    ap.add_argument("--top", type=int, default=40,
                    help="rows to print (0 = all)")
    args = ap.parse_args()

    all_rows, scoreable = eval_rows()
    supply, totals = corpus_supply()
    names = [corpus_name(p) for p in ALL_CORPORA if os.path.exists(p)]
    loaded = {corpus_name(p) for p in CORPUS_PATHS}

    # Demand: one count per eval row per technique it asks about. A row with
    # two acceptable techniques contributes to both -- it can be satisfied by
    # supply of either.
    demand = Counter()
    for _row, ids in scoreable:
        for t in ids:
            demand[t] += 1

    print(f"eval: {len(all_rows)} rows, {len(scoreable)} scoreable, "
          f"{len(demand)} distinct techniques in demand")
    print("corpora: " + ", ".join(
        f"{n} {totals[n]}" + ("" if n in loaded else " (NOT LOADED)")
        for n in names) + "\n")

    hdr = f"{'technique':>12} {'eval':>5} {'total':>6} " + \
        " ".join(f"{n:>8}" for n in names)
    print("=" * len(hdr))
    print("Demand vs supply, worst-supplied first (the shopping list)")
    print("=" * len(hdr))
    print(hdr)

    # Sort by how badly supplied a technique is *relative to how often it is
    # asked about* -- a technique with 44 eval rows and 8 corpus rows outranks
    # one with 1 eval row and 0, which is noise.
    def starvation(t):
        loaded_supply = sum(supply[t][n] for n in names if n in loaded)
        return -(demand[t] / (loaded_supply + 1))

    order = sorted(demand, key=starvation)
    shown = order if args.top == 0 else order[:args.top]
    for t in shown:
        tot = sum(supply[t][n] for n in names if n in loaded)
        cells = " ".join(f"{supply[t][n]:>8}" for n in names)
        print(f"{t:>12} {demand[t]:>5} {tot:>6} {cells}")
    if len(order) > len(shown):
        print(f"  ... {len(order) - len(shown)} more, better supplied")

    # The headline a candidate corpus has to beat.
    print("\n" + "=" * len(hdr))
    print("Demand-weighted coverage -- the statistic to shop on")
    print("=" * len(hdr))
    n_dem = sum(demand.values())
    print(f"  {'corpus':>10} {'eval demand w/ >=1 example':>28} "
          f"{'>=3':>8} {'>=20':>8}")
    for n in names:
        c1 = sum(d for t, d in demand.items() if supply[t][n] >= 1)
        c3 = sum(d for t, d in demand.items() if supply[t][n] >= 3)
        c20 = sum(d for t, d in demand.items() if supply[t][n] >= 20)
        tag = "" if n in loaded else "  (not loaded)"
        print(f"  {n:>10} {c1 / n_dem:>27.1%} {c3 / n_dem:>7.1%} "
              f"{c20 / n_dem:>7.1%}{tag}")
    c1 = sum(d for t, d in demand.items()
             if sum(supply[t][n] for n in loaded) >= 1)
    c3 = sum(d for t, d in demand.items()
             if sum(supply[t][n] for n in loaded) >= 3)
    c20 = sum(d for t, d in demand.items()
              if sum(supply[t][n] for n in loaded) >= 20)
    print(f"  {'LOADED':>10} {c1 / n_dem:>27.1%} {c3 / n_dem:>7.1%} "
          f"{c20 / n_dem:>7.1%}")

    # What a corpus would have to contain to matter. Effort 14's buckets.
    print("\n" + "=" * len(hdr))
    print("Unmet demand, by bucket (loaded corpora only)")
    print("=" * len(hdr))
    buckets = [("absent (0 examples)", lambda s: s == 0),
               ("tail (1-2)", lambda s: 1 <= s <= 2),
               ("mid (3-19)", lambda s: 3 <= s <= 19),
               ("head (>=20)", lambda s: s >= 20)]
    for label, pred in buckets:
        ts = [t for t in demand if pred(sum(supply[t][n] for n in loaded))]
        rows_ = sum(demand[t] for t in ts)
        print(f"  {label:>20} {len(ts):>4} techniques  "
              f"{rows_:>4} eval rows ({rows_ / n_dem:>5.1%})")

    vendor_breakdown(scoreable)
    supply_gradient(supply, loaded, demand)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["technique", "eval_demand", "loaded_supply"] + names)
            for t in order:
                w.writerow([t, demand[t],
                            sum(supply[t][n] for n in loaded)]
                           + [supply[t][n] for n in names])
        print(f"\nwrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
