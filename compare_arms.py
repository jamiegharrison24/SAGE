"""Tabulate the evaluation metrics across taxonomy arms.

Reads the per-arm `metrics-<dataset>.json` records the evaluation harness
writes (one baseline-dir per arm) and prints the comparison the AIF-vs-ATT&CK
study asks for: graph structure, alert compression, perplexity and timing,
each arm against the AIF baseline.

Only metrics that mean the same thing across arms are shown. Note in
particular that `n_objectives` is not a quality measure but a property of the
taxonomy: AIF distinguishes 13 high-severity stages, the hybrid ATT&CK arms 4,
and the tactic arms 1, so a lower count is aggregation rather than loss.

Usage:
    python compare_arms.py ../eval-mitre --dataset cptc-2017
"""
import argparse
import json
import os
import sys

# (label, path in the record, higher_is_better or None when it is neither)
METRICS = [
    ("attack graphs", "attack_graphs.aggregate.n_attack_graphs", None),
    ("victims", "attack_graphs.aggregate.n_victims", None),
    ("objectives", "attack_graphs.aggregate.n_objectives", None),
    ("total nodes", "attack_graphs.aggregate.total_nodes", None),
    ("unique nodes", "attack_graphs.aggregate.unique_nodes", None),
    ("total edges", "attack_graphs.aggregate.total_edges", None),
    ("unique edges", "attack_graphs.aggregate.unique_edges", None),
    ("self loops", "attack_graphs.aggregate.self_loops", None),
    ("parallel edges", "attack_graphs.aggregate.parallel_edges", None),
    ("alerts/AG (raw)", "compression.raw_alerts_per_ag", True),
    ("alerts/AG node", "compression.raw_alerts_per_ag_node", True),
    ("perplexity (train)", "perplexity.training.perplexity", False),
    ("perplexity (heldout)", "perplexity.heldout.perplexity", False),
    ("wall clock (s)", "timing.wall_clock_seconds", False),
    ("alerts/sec", "timing.alert_throughput", True),
]


def dig(record, dotted):
    node = record
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, (int, float)) and not isinstance(node, bool) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results_root")
    ap.add_argument("--dataset", default="cptc-2017")
    ap.add_argument("--baseline", default="aif")
    args = ap.parse_args()

    arms, records = [], {}
    for arm in sorted(os.listdir(args.results_root)):
        path = os.path.join(args.results_root, arm, "metrics-%s.json" % args.dataset)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                records[arm] = json.load(fh)["reference"]
            arms.append(arm)
    if args.baseline in arms:                     # baseline first
        arms.remove(args.baseline)
        arms.insert(0, args.baseline)
    if not arms:
        raise SystemExit("no metrics-%s.json found under %s" % (args.dataset, args.results_root))

    width = max(len(a) for a in arms) + 2
    print("dataset: %s    baseline: %s\n" % (args.dataset, args.baseline))
    header = "%-22s" % "metric" + "".join("%*s" % (width, a) for a in arms)
    print(header)
    print("-" * len(header))
    base = records.get(args.baseline)
    for label, dotted, higher_better in METRICS:
        cells = []
        for arm in arms:
            value = dig(records[arm], dotted)
            cells.append("--" if value is None else
                         ("%*.2f" % (width, value) if isinstance(value, float)
                          else "%*d" % (width, value)))
        print("%-22s" % label + "".join(cells))
        # Delta line against the baseline, only where a comparison is meaningful.
        if base is not None and len(arms) > 1:
            bv = dig(base, dotted)
            if bv:
                deltas = []
                for arm in arms:
                    if arm == args.baseline:
                        deltas.append("%*s" % (width, ""))
                        continue
                    v = dig(records[arm], dotted)
                    deltas.append("%*s" % (width, "--" if v is None
                                           else "%+.1f%%" % (100.0 * (v - bv) / bv)))
                print("%-22s" % "" + "".join(deltas))
    return 0


if __name__ == "__main__":
    sys.exit(main())
