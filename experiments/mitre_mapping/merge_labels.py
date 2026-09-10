"""
Merges `label_queue/labeled_batch*.csv` into one scoreable set at
`attack_mapper/data/labeled_set_v2.csv`.

Two things happen here, both deliberate:

1. **`micro_attack_stage` is joined back in, as informational metadata only.**
   Labeling was blind to it (see `label_queue/CONVENTION.md`) because the
   pipeline's `bridge_table` source used to key off it. `bridge_table` has
   since been removed entirely (see `ioc_resolver.py` and `../STATUS.md`
   effort 9 -- 70% of scoreable rows at only 34.8% accuracy, a structural
   ceiling, not a tunable one) and `validate.py` no longer passes this column
   to the pipeline. It stays in the merged CSV purely as review context (which
   coarse stage a row falls under), not as an active input to anything.

2. **The output filename deliberately does not match `hand_audit_sample*`.**
   `validate.py` globs that pattern, and these rows are `model_proposed`, not
   human-confirmed. Keeping them out of that glob stops 400 machine labels
   from silently inheriting the phrase "hand-audited" in the report.
"""
import csv
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAME = os.path.join(HERE, "archive", "ground_truth_signatures.csv")
BATCH_GLOB = os.path.join(HERE, "label_queue", "labeled_batch*.csv")
OUT = os.path.join(HERE, "attack_mapper", "data", "labeled_set_v2.csv")

FIELDS = ["signature", "micro_attack_stage", "proposed_technique", "rationale",
          "label_source", "reviewer_verdict", "reviewer_notes"]


def main():
    with open(FRAME, encoding="utf-8") as fh:
        stage_by_sig = {r["signature"].strip(): r.get("micro_attack_stage", "")
                        for r in csv.DictReader(fh)}

    rows, seen, problems = [], set(), []
    for fn in sorted(glob.glob(BATCH_GLOB)):
        with open(fn, encoding="utf-8") as fh:
            batch = list(csv.DictReader(fh))
        if len(batch) != 50:
            problems.append(f"{os.path.basename(fn)}: {len(batch)} rows, expected 50")
        for r in batch:
            sig = r["signature"].strip()
            if sig in seen:
                problems.append(f"{os.path.basename(fn)}: duplicate signature {sig!r}")
                continue
            if sig not in stage_by_sig:
                problems.append(f"{os.path.basename(fn)}: signature not in frame: {sig!r}")
            if not r.get("proposed_technique", "").strip():
                problems.append(f"{os.path.basename(fn)}: empty proposed_technique for {sig!r}")
            seen.add(sig)
            rows.append({
                "signature": sig,
                "micro_attack_stage": stage_by_sig.get(sig, ""),
                "proposed_technique": r.get("proposed_technique", "").strip(),
                "rationale": r.get("rationale", "").strip(),
                "label_source": r.get("label_source", "model_proposed").strip() or "model_proposed",
                "reviewer_verdict": r.get("reviewer_verdict", "").strip(),
                "reviewer_notes": r.get("reviewer_notes", "").strip(),
            })

    if problems:
        print("PROBLEMS:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)

    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    confirmed = sum(1 for r in rows if r["label_source"] == "human_confirmed")
    print(f"merged {len(rows)} rows from {len(glob.glob(BATCH_GLOB))} batches -> "
          f"{os.path.relpath(OUT, HERE)}")
    print(f"  human_confirmed: {confirmed}/{len(rows)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
