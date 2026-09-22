"""Does a finer mapping table actually say anything the coarser one cannot?

The companion to `tier_delta.py`. That one asks whether a *severity* change
touches the data; this asks whether a *granularity* change does. Both exist
because effort 23 read "the arms produced identical counts" as "this lever does
not matter", when it can equally mean "this lever never touched the data"
(REPORT.md section 9).

Groups every signature by its code in the coarse table, then asks whether the
fine table splits that group, and how many alerts land on the groups it splits.

The result for hybrid vs technique on cptc-2017 is worth knowing before reading
the output: the splits are real and carry 82% of the alerts, but they fall
entirely in the coarse table's *low-severity* codes, because `hybrid` already
keeps technique identity at the medium and high tiers. The two tables are
identical by construction in the only tier that can terminate an attack graph,
so that comparison could not have produced a difference in graph structure
whatever the alert volume. Check the severity column below before concluding
anything from the totals.

Usage:
    python experiments/mitre_mapping/granularity_delta.py \\
        hybrid_catchall technique_catchall --dataset cptc-2017
"""
import argparse
import collections
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)          # so tier_delta imports without a package marker

from signatures import mitre_stages  # noqa: E402
from tier_delta import alert_volume  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('coarse', help='e.g. hybrid_catchall')
    parser.add_argument('fine', help='e.g. technique_catchall')
    parser.add_argument('--dataset', default='cptc-2017')
    parser.add_argument('--top', type=int, default=10)
    args = parser.parse_args()

    coarse = importlib.import_module(
        'signatures.mitre_mapping_%s' % args.coarse).mitre_signature_to_code
    fine = importlib.import_module(
        'signatures.mitre_mapping_%s' % args.fine).mitre_signature_to_code

    volume = alert_volume(args.dataset)
    total = sum(volume.values())

    grouped = collections.defaultdict(set)
    for signature, code in coarse.items():
        grouped[code].add(signature)

    split_alerts, rows = 0, []
    high_tier_alerts = 0
    for code, signatures in grouped.items():
        distinct = {fine.get(s) for s in signatures if s in fine}
        if len(distinct) <= 1:
            continue                       # the fine table adds nothing here
        firing = {s: volume[s] for s in signatures if volume.get(s)}
        if not firing:
            continue                       # a split that this dataset never sees
        alerts = sum(firing.values())
        severity = mitre_stages.severity_of_code(code)
        split_alerts += alerts
        if severity > 1:
            high_tier_alerts += alerts
        rows.append((alerts, code, severity, len(distinct), len(firing)))

    print('dataset: %s (%d alerts)' % (args.dataset, total))
    print('coarse codes the fine table splits, and that fire here: %d' % len(rows))
    print('  alerts on them: %d (%.2f%% of the dataset)'
          % (split_alerts, 100.0 * split_alerts / total))
    print('  of which above the low tier: %d (%.2f%%)'
          % (high_tier_alerts, 100.0 * high_tier_alerts / total))
    if rows and not high_tier_alerts:
        print('\n  Every split is low-severity, so the finer table cannot change\n'
              '  which states terminate an attack graph. Identical graph counts\n'
              '  between these two tables are structural, not evidence about\n'
              '  granularity.')
    print()
    tiers = {1: 'low', 2: 'medium', 3: 'high'}
    for alerts, code, severity, distinct, firing in sorted(rows, reverse=True)[:args.top]:
        print('   %8d alerts  coarse code %-6s (%-6s) -> %2d fine codes, %d firing sigs'
              % (alerts, code, tiers.get(severity, severity), distinct, firing))


if __name__ == '__main__':
    main()
