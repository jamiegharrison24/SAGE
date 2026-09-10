"""
Builds a *blind* labeling queue from the 773-signature frame
(`archive/ground_truth_signatures.csv`), excluding rows already covered by
`attack_mapper/data/hand_audit_sample*.csv`.

Blind is the point. The pipeline's dominant candidate source is
`bridge_table`, which maps `micro_attack_stage` -> technique. A labeler who
can see `micro_attack_stage` (or the bridge-derived `gt_ids`) will largely
reproduce that mapping, and measured accuracy on bridge_table-sourced rows
inflates toward ceiling -- a bigger set that reports a *better* number while
being strictly less informative. The existing 100 rows earn their value by
disagreeing with the bridge (e.g. Shellshock ARBITRARY_CODE_EXE -> T1203
rejected for T1190), which is only possible if the stage wasn't visible.

So the queue carries `signature` and nothing else. `micro_attack_stage` is
joined back in afterwards by `merge_labels.py`, for scoring only.
"""
import argparse
import csv
import glob
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FRAME = os.path.join(HERE, "archive", "ground_truth_signatures.csv")
AUDIT_GLOB = os.path.join(HERE, "attack_mapper", "data", "hand_audit_sample*.csv")
QUEUE_DIR = os.path.join(HERE, "label_queue")


def already_labeled():
    seen = set()
    for fn in sorted(glob.glob(AUDIT_GLOB)):
        with open(fn, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                seen.add(row["signature"].strip())
    for fn in sorted(glob.glob(os.path.join(QUEUE_DIR, "labeled_batch*.csv"))):
        with open(fn, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                seen.add(row["signature"].strip())
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-size", type=int, default=50)
    ap.add_argument("--target", type=int, default=400,
                    help="how many new rows to queue (100 already labeled -> 400 reaches 500)")
    args = ap.parse_args()

    seen = already_labeled()
    with open(FRAME, encoding="utf-8") as fh:
        frame = list(csv.DictReader(fh))

    pending = [r["signature"].strip() for r in frame if r["signature"].strip() not in seen]
    pending = sorted(set(pending))[: args.target]

    os.makedirs(QUEUE_DIR, exist_ok=True)
    written = []
    for i in range(0, len(pending), args.batch_size):
        chunk = pending[i:i + args.batch_size]
        n = i // args.batch_size + 1
        path = os.path.join(QUEUE_DIR, f"queue_batch{n:02d}.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["signature"])
            for sig in chunk:
                w.writerow([sig])
        written.append((path, len(chunk)))

    print(f"already labeled: {len(seen)}")
    print(f"queued: {len(pending)} rows across {len(written)} batches")
    for path, n in written:
        print(f"  {os.path.relpath(path, HERE)}  ({n} rows)")


if __name__ == "__main__":
    main()
