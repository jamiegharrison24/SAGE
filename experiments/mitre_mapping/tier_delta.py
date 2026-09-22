"""Do the signatures that change severity tier between two variants actually fire?

Two severity variants can produce byte-identical attack graphs for either of
two reasons: the runs shared a result (a caching bug this branch has already
hit once -- see REPORT.md section 9) or the signatures whose tier changed
simply never appear in the dataset. They look the same in the metrics and mean
opposite things, so the question has to be settled against the alerts.

This reports, for a pair of generated mapping tables, how many signatures
change tier and what share of the dataset's alert volume lands on them.

Usage:
    python experiments/mitre_mapping/tier_delta.py \\
        mitre_var_killchain mitre_var_impactonly --dataset cptc-2017
"""
import argparse
import collections
import glob
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from signatures import mitre_stages  # noqa: E402


def signature_of(record):
    """The alert signature, across the three JSON shapes the datasets use.

    cptc-2017/2018 wrap alerts in a Splunk-style `result` object (sometimes
    with the original JSON stringified in `_raw`); ccdc stores Suricata's own
    `alert` object directly. Returning None for anything unrecognised would
    silently zero a dataset, so callers assert a non-zero count.
    """
    result = record.get('result') if isinstance(record, dict) else None
    if isinstance(result, dict):
        if result.get('alert.signature'):
            return result['alert.signature']
        raw = result.get('_raw')
        if raw:
            try:
                return json.loads(raw).get('alert', {}).get('signature')
            except ValueError:
                return None
    raw = record.get('_raw') if isinstance(record, dict) else None
    if raw:
        try:
            return json.loads(raw).get('alert', {}).get('signature')
        except ValueError:
            return None
    alert = record.get('alert') if isinstance(record, dict) else None
    return alert.get('signature') if isinstance(alert, dict) else None


def alert_volume(dataset):
    """Signature -> alert count for one dataset."""
    volume = collections.Counter()
    pattern = os.path.join(ROOT, 'alerts', dataset, '*.json')
    for filename in sorted(glob.glob(pattern)):
        with open(filename, encoding='utf-8', errors='replace') as handle:
            for record in json.load(handle):
                signature = signature_of(record)
                if signature:
                    volume[signature.strip()] += 1
    if not volume:
        raise SystemExit('no alerts read from %s -- decompress alerts/ first, '
                         'or the JSON shape is unrecognised' % pattern)
    return volume


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', help='e.g. mitre_var_killchain')
    parser.add_argument('right', help='e.g. mitre_var_impactonly')
    parser.add_argument('--dataset', default='cptc-2017')
    parser.add_argument('--top', type=int, default=10)
    args = parser.parse_args()

    left = importlib.import_module('signatures.mitre_mapping_%s'
                                   % args.left[len('mitre_'):]).mitre_signature_to_code
    right = importlib.import_module('signatures.mitre_mapping_%s'
                                    % args.right[len('mitre_'):]).mitre_signature_to_code

    severity = mitre_stages.severity_of_code
    moved = {s for s in left if s in right and severity(left[s]) != severity(right[s])}
    print('signatures changing tier between %s and %s: %d'
          % (args.left, args.right, len(moved)))

    volume = alert_volume(args.dataset)
    total = sum(volume.values())
    hits = collections.Counter({s: n for s, n in volume.items() if s in moved})
    fired = sum(hits.values())
    print('alerts in %s: %d' % (args.dataset, total))
    print('alerts on tier-changing signatures: %d (%.3f%%)'
          % (fired, 100.0 * fired / total))
    if not fired:
        print('\n  None fire. Identical graph output between these two variants '
              'is the correct result, not a shared or cached run.')
    for signature, count in hits.most_common(args.top):
        print('   %6d  %-62s  %s -> %s'
              % (count, signature[:62], left[signature], right[signature]))


if __name__ == '__main__':
    main()
