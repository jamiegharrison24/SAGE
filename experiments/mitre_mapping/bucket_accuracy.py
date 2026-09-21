"""Head/mid/tail bucket accuracy from a validate.py report.

Effort 14 (`corpus_coverage_findings.md`, "Accuracy tracks how many training
examples a technique has") computed this once, ad hoc, to show that micro is
carried by three head classes and macro hides the tail. `typed_markers_prereg.md`
pre-registers bucket accuracy (not micro/macro) as the criterion for effort
17, so this makes that check repeatable instead of hand-done per report.

Bucket boundaries (fixed, matching effort 14 exactly so numbers are
comparable across reports): head >=20 eval examples, mid 3-19, tail <=2 --
counted from the SAME report's scoreable rows, which is why two reports over
the same 361-row eval set always bucket every technique identically; only
per-bucket accuracy can differ between them.

Usage:
    python bucket_accuracy.py validation_report.md
    python bucket_accuracy.py report_a.md report_b.md   # side-by-side diff
"""
import re
import sys

ROW_RE = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|(?:\s*([^|]+?)\s*\|)?\s*([^|]+?)\s*\|\s*$")


def parse_report(path):
    """Returns {true_label: [(hit: bool, signature), ...]}, MISS/HIT rows
    only -- SKIPPED (ambiguous/tactic-only) rows are already excluded from
    `scoreable` upstream and must not be counted here either."""
    rows = []
    section = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("## Miss / skip rows"):
                section = "miss"
                continue
            if line.startswith("## Hit rows"):
                section = "hit"
                continue
            if line.startswith("## ") and section is not None:
                section = None
                continue
            if section is None or not line.startswith("|"):
                continue
            if line.startswith("|---") or line.startswith("| proposed") or line.startswith("| true"):
                continue
            m = ROW_RE.match(line)
            if not m:
                continue
            if section == "hit":
                true_label, _pred, signature = m.group(1), m.group(2), m.group(4)
                rows.append((true_label, True, signature))
            else:
                true_label, _pred, verdict, signature = m.groups()
                if verdict != "MISS":  # drop SKIPPED
                    continue
                rows.append((true_label, False, signature))
    by_label = {}
    for true_label, hit, sig in rows:
        by_label.setdefault(true_label, []).append((hit, sig))
    return by_label


def bucket_of(n):
    if n >= 20:
        return "head"
    if n >= 3:
        return "mid"
    return "tail"


def bucket_accuracy(by_label):
    buckets = {"head": [0, 0], "mid": [0, 0], "tail": [0, 0]}  # [hits, total]
    classes = {"head": set(), "mid": set(), "tail": set()}
    for label, rows in by_label.items():
        b = bucket_of(len(rows))
        classes[b].add(label)
        buckets[b][0] += sum(1 for hit, _ in rows if hit)
        buckets[b][1] += len(rows)
    return buckets, classes


def report(path):
    by_label = parse_report(path)
    buckets, classes = bucket_accuracy(by_label)
    total_hits = sum(h for h, _ in buckets.values())
    total_rows = sum(n for _, n in buckets.values())
    print(f"{path}")
    print(f"  {total_rows} scoreable rows, {len(by_label)} distinct true labels, "
         f"micro {total_hits}/{total_rows} = {total_hits / total_rows:.1%}" if total_rows else "  no rows parsed")
    for b in ("head", "mid", "tail"):
        h, n = buckets[b]
        acc = h / n if n else 0.0
        print(f"  {b:>4} ({len(classes[b]):>2} classes, {n:>3} rows): "
             f"{h:>3}/{n:<3} = {acc:.1%}")
    return buckets


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    results = [report(p) for p in sys.argv[1:]]
    if len(results) == 2:
        print("\ndelta (second - first), percentage points:")
        for b in ("head", "mid", "tail"):
            h1, n1 = results[0][b]
            h2, n2 = results[1][b]
            a1 = h1 / n1 if n1 else 0.0
            a2 = h2 / n2 if n2 else 0.0
            print(f"  {b:>4}: {a1:.1%} -> {a2:.1%}  ({(a2 - a1) * 100:+.1f} pts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
