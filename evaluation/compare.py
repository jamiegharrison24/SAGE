"""
Distortion measures between two runs.

Used for three things: comparing a perturbed run against its reference run,
comparing a swept-parameter run against its dataset's baseline, and checking
whether repeat runs are byte-identical.

**On byte comparison.** The `baseline-v1` tree predates the tooltip-ordering fix
(`ag_generation.py`: `"\\n".join(sorted(signatures))`). At the baseline, that join
is unsorted over a `set`, and Python randomises string hashing per process, so
`.dot` bytes differ between runs for that reason alone. Comparing raw bytes there
would report the pipeline as non-deterministic and, per the spec, trigger a loud
recommendation that the regression reference needs tolerance bands -- on the
strength of an artifact-formatting artefact rather than any real instability.
`normalise_dot` therefore sorts tooltip contents before comparing, and the record
reports the normalised and raw verdicts side by side so the distinction is
visible rather than assumed away.
"""
import hashlib
import os
import re

# Signature lists inside tooltips; unsorted at baseline-v1 (see module docstring).
_TOOLTIP = re.compile(r'(tooltip=")((?:[^"\\]|\\.)*)(")')

# Absolute paths and wall-clock timestamps legitimately differ between runs of
# the same configuration and say nothing about determinism.
_TIMESTAMP = re.compile(r'\d{2}/\d{2}/\d{2}, \d{2}:\d{2}:\d{2}')


def normalise_dot(text, sort_tooltips=True, mask_timestamps=False):
    """
    Canonicalises `.dot` text so that two runs of the same configuration compare
        equal when they differ only in incidental formatting.

    @param text: the .dot source
    @param sort_tooltips: sort the newline-separated signature list inside each
        tooltip, neutralising baseline-v1's unsorted set join
    @param mask_timestamps: also blank out rendered wall-clock timestamps; only
        appropriate when comparing runs that are not expected to align in time
    @return: the normalised text
    """
    if sort_tooltips:
        def sort_one(match):
            signatures = match.group(2).split('\\n')
            return match.group(1) + '\\n'.join(sorted(signatures)) + match.group(3)
        text = _TOOLTIP.sub(sort_one, text)
    if mask_timestamps:
        text = _TIMESTAMP.sub('<TS>', text)
    # Statement order within a file is not semantically meaningful here.
    return '\n'.join(sorted(line.rstrip() for line in text.splitlines() if line.strip()))


def file_digest(path, normaliser=None):
    """
    Hashes a file, optionally after normalising its text.

    @param path: the file to hash
    @param normaliser: an optional text -> text callable
    @return: the hex SHA-256
    """
    if normaliser is None:
        with open(path, 'rb') as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    with open(path, 'r', encoding='utf-8') as handle:
        return hashlib.sha256(normaliser(handle.read()).encode('utf-8')).hexdigest()


def jaccard(left, right):
    """
    Computes the Jaccard index of two sets, defining the empty-vs-empty case as
        1.0 (identical) rather than undefined.

    @param left: a set
    @param right: a set
    @return: |intersection| / |union|
    """
    left, right = set(left), set(right)
    if not left and not right:
        return 1.0
    return len(left & right) / len(left | right)


def compare_ag_directories(reference, candidate):
    """
    Compares two attack graph directories: which graphs were gained or lost, and
        how far the node and edge sets moved.

    @param reference: metrics dict from `dot_metrics.directory_metrics` for the
        reference run, produced with node/edge sets retained
    @param candidate: the same for the run being compared
    @return: a dict of distortion measures
    """
    ref_graphs = {(g['victim'], g['objective']) for g in reference['per_graph']}
    cand_graphs = {(g['victim'], g['objective']) for g in candidate['per_graph']}

    ref_nodes, ref_edges = _collect_sets(reference)
    cand_nodes, cand_edges = _collect_sets(candidate)

    return {
        'node_jaccard': jaccard(ref_nodes, cand_nodes),
        'edge_jaccard': jaccard(ref_edges, cand_edges),
        'graph_jaccard': jaccard(ref_graphs, cand_graphs),
        'ags_gained': sorted('{}|{}'.format(v, o) for v, o in cand_graphs - ref_graphs),
        'ags_lost': sorted('{}|{}'.format(v, o) for v, o in ref_graphs - cand_graphs),
        'n_ags_gained': len(cand_graphs - ref_graphs),
        'n_ags_lost': len(ref_graphs - cand_graphs),
        'metric_deltas': metric_deltas(reference['aggregate'], candidate['aggregate']),
    }


def _collect_sets(metrics):
    """
    Pulls the node and edge unions out of a directory metrics dict.

    @param metrics: a `dot_metrics.directory_metrics` result
    @return: (nodes, edges) as sets, empty if the sets were not retained
    """
    nodes, edges = set(), set()
    for graph in metrics['per_graph']:
        nodes.update(graph.get('_nodes', ()))
        edges.update(graph.get('_edges', ()))
    return nodes, edges


def metric_deltas(reference, candidate):
    """
    Computes absolute and relative deltas for every numeric metric two records share.

    @param reference: the reference metrics dict
    @param candidate: the candidate metrics dict
    @return: metric name -> {reference, candidate, absolute, relative}
    """
    deltas = {}
    for key, ref_value in reference.items():
        cand_value = candidate.get(key)
        if not _numeric(ref_value) or not _numeric(cand_value):
            continue
        absolute = cand_value - ref_value
        deltas[key] = {
            'reference': ref_value,
            'candidate': cand_value,
            'absolute': absolute,
            'relative': (absolute / ref_value) if ref_value else None,
        }
    return deltas


def elasticity(metric_relative_change, parameter_relative_change):
    """
    Computes the elasticity of a metric with respect to a swept parameter, i.e.
        the relative change in the metric per relative change in the parameter.

    @param metric_relative_change: the metric's relative change
    @param parameter_relative_change: the parameter's relative change
    @return: the elasticity, or None where it is undefined
    """
    if not parameter_relative_change or metric_relative_change is None:
        return None
    return metric_relative_change / parameter_relative_change


def _numeric(value):
    """
    Reports whether a value is a real number (and not a bool, which is an int
        in Python but never a metric).

    @param value: any value
    @return: True if it can take part in a delta
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def exact_match_report(run_directories, filenames, normalise=True):
    """
    Checks whether the named artifacts are identical across a set of repeat runs,
        reporting the normalised and raw verdicts separately.

    @param run_directories: the per-run output directories
    @param filenames: artifact filenames to compare, relative to each directory
    @param normalise: whether to also report the normalised verdict for .dot files
    @return: filename -> {identical_raw, identical_normalised, n_runs, digests}
    """
    report = {}
    for filename in filenames:
        paths = [os.path.join(directory, filename) for directory in run_directories]
        present = [p for p in paths if os.path.exists(p)]
        if len(present) != len(paths):
            report[filename] = {'error': 'missing in {} of {} runs'
                                         .format(len(paths) - len(present), len(paths))}
            continue
        raw = {file_digest(p) for p in present}
        entry = {'identical_raw': len(raw) == 1, 'n_runs': len(present),
                 'n_distinct_raw': len(raw)}
        if normalise and filename.endswith('.dot'):
            norm = {file_digest(p, normalise_dot) for p in present}
            entry['identical_normalised'] = len(norm) == 1
            entry['n_distinct_normalised'] = len(norm)
        report[filename] = entry
    return report
