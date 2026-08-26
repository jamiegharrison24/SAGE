"""
The versioned result record, and the regression check that makes it a reference.

A stored record is only a *reference* if a later run can be diffed against it
mechanically. That requires two things this module provides: a stable shape
(`SCHEMA_VERSION`, so the MITRE-mapping work can emit the same record type for
direct comparison), and an explicit tolerance per metric.

**On tolerances.** A tolerance of zero is a claim that the pipeline is
deterministic for that metric. That claim is checked, not assumed: the repeat
runs in the matrix are what establish it, and until they have run the
conservative defaults here apply. Runtime is deliberately excluded from
pass/fail -- it is hardware-dependent and would make the check fail on a
different machine for reasons that have nothing to do with a regression -- but
it is still recorded and reported as drift.
"""
import json
import platform
from datetime import datetime, timezone

SCHEMA_VERSION = 1

# Relative tolerance per metric. None means "record the drift but never fail on
# it". Structural counts default to exact: if the repeat runs show the pipeline
# is not deterministic, these must be widened and the fact stated loudly, per the
# task spec -- not quietly relaxed to make a check pass.
TOLERANCES = {
    'n_attack_graphs': 0.0,
    'n_victims': 0.0,
    'n_objectives': 0.0,
    'total_nodes': 0.0,
    'total_edges': 0.0,
    'unique_nodes': 0.0,
    'unique_edges': 0.0,
    'self_loops': 0.0,
    'parallel_edges': 0.0,
    'raw_records': 0.0,
    'raw_alerts': 0.0,
    'perplexity_training': 1e-9,      # Float reassociation only
    'perplexity_heldout': 1e-9,
    'wall_clock_seconds': None,       # Hardware-dependent; reported, never fatal
    'alert_throughput': None,
}

# Metrics whose drift is informational rather than a regression.
NON_FATAL = {name for name, tolerance in TOLERANCES.items() if tolerance is None}


def new_record(dataset, worktree_commit, environment, iana):
    """
    Creates an empty result record with its metadata filled in.

    @param dataset: the dataset key, e.g. 'cptc-2017'
    @param worktree_commit: the commit that was measured
    @param environment: the fingerprint from `runner.environment_fingerprint`
    @param iana: the pinned-CSV record from `runner.snapshot_iana`
    @return: a record dict
    """
    return {
        'schema_version': SCHEMA_VERSION,
        'dataset': dataset,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'measured_commit': worktree_commit,
        'environment': environment,
        'iana': iana,
        'host': platform.node(),
        'reference': {},        # The single reference run
        'repeats': {},          # N identical runs -> variance and exact-match
        'perturbations': [],    # Noise injection cells
        'sweeps': [],           # -t / -w sensitivity cells
        'notes': [],            # Choices and caveats surfaced to the reader
    }


def add_note(record, note):
    """
    Records a caveat or a choice that a reader of the baseline needs to see.

    @param record: the record to annotate
    @param note: the note text
    """
    if note not in record['notes']:
        record['notes'].append(note)


def summarise(values):
    """
    Summarises repeat-run values as the spec requires: min, median, max, stdev.

    @param values: the per-repeat values
    @return: a dict, with nulls where undefined
    """
    present = sorted(v for v in values if v is not None)
    if not present:
        return {'n': 0, 'min': None, 'median': None, 'max': None,
                'mean': None, 'stdev': None}
    midpoint = len(present) // 2
    median = (present[midpoint] if len(present) % 2
              else (present[midpoint - 1] + present[midpoint]) / 2)
    mean = sum(present) / len(present)
    if len(present) > 1:
        variance = sum((v - mean) ** 2 for v in present) / (len(present) - 1)
        stdev = variance ** 0.5
    else:
        stdev = 0.0
    return {'n': len(present), 'min': present[0], 'median': median,
            'max': present[-1], 'mean': mean, 'stdev': stdev}


def flatten_metrics(record_section):
    """
    Pulls the comparable scalar metrics out of a record section.

    Only scalars participate in a regression check; per-graph detail and formula
    strings are stored for re-derivation, not compared.

    @param record_section: a record's 'reference' section
    @return: metric name -> value
    """
    flat = {}
    aggregate = record_section.get('attack_graphs', {}).get('aggregate', {})
    for key, value in aggregate.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            flat[key] = value

    counts = record_section.get('alerts', {}).get('totals', {})
    for key, value in counts.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            flat[key] = value

    for label in ('training', 'heldout'):
        scored = record_section.get('perplexity', {}).get(label, {})
        if scored.get('perplexity') is not None:
            flat['perplexity_' + label] = scored['perplexity']

    timing = record_section.get('timing', {})
    for key in ('wall_clock_seconds', 'alert_throughput'):
        if isinstance(timing.get(key), (int, float)):
            flat[key] = timing[key]

    return flat


def check_regression(baseline_record, candidate_record, tolerances=None):
    """
    Diffs a fresh run against a stored baseline.

    This is what turns the snapshot from a document into a reference: it decides,
    mechanically, whether the pipeline still behaves as recorded.

    @param baseline_record: the stored record
    @param candidate_record: the freshly produced record
    @param tolerances: metric -> relative tolerance, or None for the defaults
    @return: a dict with 'passed', the per-metric findings, and any schema warning
    """
    tolerances = TOLERANCES if tolerances is None else tolerances
    baseline = flatten_metrics(baseline_record.get('reference', {}))
    candidate = flatten_metrics(candidate_record.get('reference', {}))

    findings, failures = [], []
    for metric, expected in sorted(baseline.items()):
        actual = candidate.get(metric)
        if actual is None:
            findings.append({'metric': metric, 'status': 'missing',
                             'expected': expected, 'actual': None})
            if metric not in NON_FATAL:
                failures.append(metric)
            continue

        absolute = actual - expected
        relative = (absolute / expected) if expected else (0.0 if not absolute else None)
        tolerance = tolerances.get(metric, 0.0)

        if tolerance is None:
            status = 'informational'
        elif relative is None:
            status = 'fail'
        elif abs(relative) <= tolerance:
            status = 'ok'
        else:
            status = 'fail'

        if status == 'fail':
            failures.append(metric)
        findings.append({'metric': metric, 'status': status, 'expected': expected,
                         'actual': actual, 'absolute': absolute, 'relative': relative,
                         'tolerance': tolerance})

    new_metrics = sorted(set(candidate) - set(baseline))
    result = {
        'passed': not failures,
        'n_compared': len(baseline),
        'failures': failures,
        'findings': findings,
        'new_metrics': new_metrics,
    }

    stored_version = baseline_record.get('schema_version')
    if stored_version != SCHEMA_VERSION:
        result['schema_warning'] = (
            'Baseline was written with schema_version {} but this is version {}; '
            'the comparison may not be meaningful.'.format(stored_version, SCHEMA_VERSION))
    return result


def save(record, path):
    """
    Writes a record to disk as formatted, key-sorted JSON so that two records can
        be diffed with ordinary text tools.

    @param record: the record to write
    @param path: the destination path
    """
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(record, handle, indent=2, sort_keys=True, default=str)
        handle.write('\n')


def load(path):
    """
    Reads a record from disk.

    @param path: the record path
    @return: the record dict
    """
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)
