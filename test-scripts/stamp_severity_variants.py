"""Records which severity table produced each sensitivity arm's metrics.

The evaluation harness records provenance as a commit SHA
(`evaluation/runner.py:git_commit`). That is enough when arms differ by
committed code, but the severity variants differ by a *generated, gitignored*
table -- so all four arms carry the same SHA and the deciding input is not in
git at all. Without this stamp, a metrics file on disk cannot be attributed to
the table that produced it.

Writes `<arm>/variant.json`: the environment that selected the table, the tier
counts, the table's sha256, and the command that regenerates it.

Usage (after test-scripts/run_severity_sensitivity.sh):
    python test-scripts/stamp_severity_variants.py ../eval-sensitivity
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# arm directory -> (SAGE_SEVERITY_VARIANT, SAGE_TAXONOMY). The AIF baseline
# has no variant: its severity is published, which is the whole point of the
# comparison.
ARMS = {
    'aif': (None, 'aif'),
    'kill-chain': ('kill-chain', 'mitre_var_killchain'),
    'aif-aligned': ('aif-aligned', 'mitre_var_aifaligned'),
    'impact-only': ('impact-only', 'mitre_var_impactonly'),
}

PROBE = ("from signatures import taxonomy as t;"
         "import collections, json;"
         "c = collections.Counter(t.severity(k) for k in t.symbol_table());"
         "print(json.dumps({'low': c[1], 'medium': c[2], 'high': c[3]}))")


def stamp(results_root, arm, variant, taxonomy, commit):
    """Writes one arm's variant.json. Returns the table digest, or None for
    the AIF baseline, which has no generated table."""
    record = {'arm': arm, 'commit': commit, 'SAGE_TAXONOMY': taxonomy,
              'SAGE_SEVERITY_VARIANT': variant}

    if variant is not None:
        relative = os.path.join('signatures',
                                'mitre_mapping_%s.py' % taxonomy[len('mitre_'):])
        with open(os.path.join(ROOT, relative), 'rb') as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        record.update({
            'table': relative.replace(os.sep, '/'),
            'table_tracked': False,
            'table_sha256': digest,
            'regenerate': ('SAGE_SEVERITY_VARIANT=%s python3 -m '
                           'signatures.build_mitre_mapping --level hybrid '
                           '--unmapped catchall --out %s'
                           % (variant, relative.replace(os.sep, '/'))),
        })
        # Counts come from the taxonomy layer rather than the build log, so
        # they describe what the pipeline actually loaded. Includes the
        # `unmapped` catchall code, so `low` is one higher than the build
        # script's own tally of tactics.
        env = dict(os.environ, SAGE_TAXONOMY=taxonomy,
                   SAGE_SEVERITY_VARIANT=variant, PYTHONHASHSEED='0')
        probe = subprocess.run([sys.executable, '-c', PROBE], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, universal_newlines=True)
        record['codes_by_severity'] = json.loads(probe.stdout)

    with open(os.path.join(results_root, arm, 'variant.json'), 'w') as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write('\n')
    return record.get('table_sha256')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results_root',
                        help='directory holding one subdirectory per arm')
    args = parser.parse_args()

    commit = subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'],
                            stdout=subprocess.PIPE,
                            universal_newlines=True).stdout.strip()

    for arm in sorted(ARMS):
        if not os.path.isdir(os.path.join(args.results_root, arm)):
            print('skipped %-12s (not run)' % arm)
            continue
        digest = stamp(args.results_root, arm, ARMS[arm][0], ARMS[arm][1], commit)
        print('stamped %-12s %s' % (arm, (digest or '(AIF baseline)')[:16]))


if __name__ == '__main__':
    main()
