"""
Assembles a completed run cell's artifacts into a schema record section.

This is the seam between "a run happened" (`runner`) and "here are its numbers"
(`schema`, `report`): it reads only files on disk, so it can be re-run over an
old cell without re-running SAGE, and a metric definition can be corrected and
re-applied to an existing matrix without burning the compute again.
"""
import os
import re

from evaluation import alerts, compare, dot_metrics, perplexity

# Printed by alert_loading/sage.py once per team file.
_READ_ALERTS = re.compile(r'Reading # alerts:\s+(\d+)')
_FILTERED_ALERTS = re.compile(r'Filtered # alerts \(remaining\):\s*(\d+)')


def measure_cell(cell_record, dataset_path, dataset_flag, alert_counts=None):
    """
    Turns one completed cell into a record section.

    @param cell_record: the record returned by `runner.execute_cell`
    @param dataset_path: the alerts directory the cell was run against
    @param dataset_flag: 'cptc' or 'other'
    @param alert_counts: a precomputed `alerts.count_directory` result, since
        counting CCDC's ~1M alerts for every cell of a matrix is wasteful
    @return: a record section with attack graph, perplexity, alert and timing data
    @raise FileNotFoundError: if the cell produced no artifacts
    """
    artifacts = cell_record.get('artifacts')
    if not artifacts:
        raise FileNotFoundError(
            'Cell {!r} has no artifacts; it did not complete (exit code {}).'
            .format(cell_record.get('name'), cell_record.get('exit_code')))

    graphs = dot_metrics.directory_metrics(artifacts['ag_directory'])

    counts = alert_counts or alerts.count_directory(dataset_path, dataset_flag)
    totals = counts['totals']

    aggregate = graphs['aggregate']
    from_log = alert_counts_from_log(cell_record)
    ratios = alerts.compression_ratios(
        raw_records=totals['raw_records'],
        raw_alerts=totals['raw_alerts'],
        post_dedup_alerts=from_log['post_dedup'],
        n_attack_graphs=aggregate['n_attack_graphs'],
        total_ag_nodes=aggregate['total_nodes'],
        unique_ag_nodes=aggregate['unique_nodes'])

    wall_clock = cell_record['wall_clock_seconds']
    section = {
        'attack_graphs': _without_sets(graphs),
        'alerts': {'totals': totals, 'n_files': counts['n_files'],
                   'per_file': counts['per_file'],
                   'from_sage_stdout': from_log,
                   # Two independent counts of the same thing: this package's
                   # parser and SAGE's own tally. They must agree; if they do
                   # not, one of the two is wrong and every alert-derived metric
                   # is suspect, so the disagreement is recorded rather than
                   # silently resolved in favour of either.
                   'counter_agrees_with_sage': (
                       None if from_log['sage_read'] is None
                       else from_log['sage_read'] == totals['raw_alerts'])},
        'compression': ratios,
        'perplexity': {'training': _score_training(artifacts)},
        'timing': {
            'wall_clock_seconds': wall_clock,
            'stages': cell_record['stages'],
            'alert_throughput': (totals['raw_records'] / wall_clock) if wall_clock else None,
            'throughput_formula': 'raw_records / wall_clock_seconds',
        },
        'argv': cell_record['argv'],
        'measured_commit': cell_record.get('measured_commit'),
    }
    return section


def score_heldout(artifacts, worktree, work_directory,
                  test_fraction=perplexity.DEFAULT_TEST_FRACTION,
                  seed=perplexity.DEFAULT_SPLIT_SEED):
    """
    Scores held-out perplexity: split the traces, relearn, score the unseen ones.

    Requires a **second FlexFringe run**, because held-out perplexity is
    meaningless against a model that was trained on the test traces. The split is
    therefore at the trace level and happens before learning, not after.

    Reported separately from training perplexity and never conflated with it: the
    training figure is the one comparable to the original SAGE paper, the held-out
    figure is the one that says whether the model generalises.

    @param artifacts: the cell's harvested artifact paths
    @param worktree: the SAGE tree holding the FlexFringe binary
    @param work_directory: a scratch directory for the split model
    @param test_fraction: the held-out proportion
    @param seed: the pinned split seed, recorded in the output
    @return: the perplexity record, or a reason it is absent
    """
    from evaluation import flexfringe

    if '.txt' not in artifacts:
        return {'perplexity': None, 'absent_because': 'no trace file in artifacts'}

    traces = perplexity.read_traces(artifacts['.txt'])
    train, test = perplexity.split_traces(traces, test_fraction, seed)

    # A split that leaves too little to learn from, or nothing to score, produces
    # a number that looks fine and means nothing. Say so instead.
    if len(train) < 10 or not test:
        return {'perplexity': None, 'n_train': len(train), 'n_test': len(test),
                'split_seed': seed, 'test_fraction': test_fraction,
                'absent_because': 'degenerate split: {} train / {} test traces'
                                  .format(len(train), len(test))}

    os.makedirs(work_directory, exist_ok=True)
    train_path = os.path.join(work_directory, 'heldout-train.txt')
    perplexity.write_traces(train, train_path)

    learned = flexfringe.run(train_path, worktree)
    automaton = perplexity.Automaton(learned['main_model'], learned['sinks_model'])

    # The test set can contain symbols the training split never had; the union
    # alphabet keeps those finite instead of infinite (see perplexity.OOV_POLICY).
    test_alphabet = {symbol.split(':')[0] for trace in test for symbol in trace}
    scored = perplexity.score(automaton, test, extra_alphabet=test_alphabet)
    scored.update({
        'n_train': len(train), 'n_test': len(test),
        'split_seed': seed, 'test_fraction': test_fraction,
        'requires_separate_model': True,
        'model_learned_from': train_path,
        'note': 'Held-out: a second FlexFringe run on the training split only. '
                'Not comparable to the training perplexity, and never averaged with it.',
    })
    return scored


def _score_training(artifacts):
    """
    Scores training perplexity from a cell's model and trace artifacts.

    @param artifacts: the cell's harvested artifact paths
    @return: the perplexity record, or a reason it is absent
    """
    required = ('.txt', '.txt.ff.final.json', '.txt.ff.finalsinks.json')
    missing = [suffix for suffix in required if suffix not in artifacts]
    if missing:
        return {'perplexity': None, 'absent_because': 'missing artifacts: {}'.format(missing)}

    automaton = perplexity.Automaton(artifacts['.txt.ff.final.json'],
                                     artifacts['.txt.ff.finalsinks.json'])
    return perplexity.score(automaton, perplexity.read_traces(artifacts['.txt']))


def alert_counts_from_log(cell_record):
    """
    Recovers SAGE's own alert counts from the run's stdout.

    Preferred over reimplementing `_remove_duplicates` here: a reimplementation
    that drifted from SAGE's own filter would silently produce a wrong
    compression ratio, whereas the numbers SAGE printed cannot drift from what
    SAGE did.

    SAGE prints these **once per team file**, not once per run, so both figures
    are sums across files -- taking the first match yields only the first team's
    count. The per-file lists are returned too, since `sage_read` should equal
    this package's independently derived `raw_alerts` and disagreement means one
    of the two counters is wrong.

    @param cell_record: the cell record, whose output directory holds stdout.log
    @return: a dict with the summed and per-file counts, or Nones if unavailable
    """
    empty = {'sage_read': None, 'post_dedup': None,
             'per_file_read': [], 'per_file_post_dedup': []}
    trace = (cell_record.get('artifacts') or {}).get('.txt')
    if not trace:
        return empty
    log_path = os.path.join(os.path.dirname(trace), 'stdout.log')
    if not os.path.exists(log_path):
        return empty

    read, filtered = [], []
    with open(log_path, 'r', encoding='utf-8', errors='replace') as handle:
        for line in handle:
            read_match = _READ_ALERTS.search(line)
            if read_match:
                read.append(int(read_match.group(1)))
                continue
            filtered_match = _FILTERED_ALERTS.search(line)
            if filtered_match:
                filtered.append(int(filtered_match.group(1)))

    return {'sage_read': sum(read) if read else None,
            'post_dedup': sum(filtered) if filtered else None,
            'per_file_read': read,
            'per_file_post_dedup': filtered}


def _without_sets(graphs):
    """
    Strips the node/edge sets from a metrics dict before it is stored.

    Every node name in every graph would bloat the record by orders of magnitude;
    the counts derived from them are kept.

    @param graphs: a `dot_metrics.directory_metrics` result
    @return: the same structure without the underscore-prefixed set keys
    """
    return {
        'aggregate': graphs['aggregate'],
        'distribution': graphs['distribution'],
        'formulas': graphs['formulas'],
        'edge_bases': graphs['edge_bases'],
        'per_graph': [{k: v for k, v in graph.items() if not k.startswith('_')}
                      for graph in graphs['per_graph']],
    }


def summarise_repeats(sections):
    """
    Summarises N identical runs into variance figures per metric.

    @param sections: the record sections from each repeat
    @return: metric -> min/median/max/stdev summary
    """
    from evaluation.schema import flatten_metrics, summarise

    flattened = [flatten_metrics({'attack_graphs': s['attack_graphs'],
                                  'alerts': s['alerts'],
                                  'perplexity': s['perplexity'],
                                  'timing': s['timing']}) for s in sections]
    metrics = sorted({name for flat in flattened for name in flat})
    return {name: summarise([flat.get(name) for flat in flattened]) for name in metrics}


def exact_match_across_repeats(cell_records):
    """
    Reports whether repeat runs produced byte-identical artifacts.

    Reported twice: raw, and after normalising `.dot` tooltip ordering. At
    `baseline-v1` the tooltip join is unsorted over a set, so raw `.dot` bytes
    differ between runs for that reason alone -- which would otherwise read as
    pipeline non-determinism and trigger a recommendation for tolerance bands
    on the strength of a formatting artefact.

    @param cell_records: the completed cell records for the repeats
    @return: a dict with the per-artifact verdicts and an overall summary
    """
    directories, traces, models = [], [], []
    for record in cell_records:
        artifacts = record.get('artifacts') or {}
        if 'ag_directory' in artifacts:
            directories.append(artifacts['ag_directory'])
        if '.txt' in artifacts:
            traces.append(artifacts['.txt'])
        if '.txt.ff.final.json' in artifacts:
            models.append(artifacts['.txt.ff.final.json'])

    verdict = {
        'traces_identical': _all_identical(traces),
        'main_model_identical': _all_identical(models),
        'n_repeats': len(cell_records),
    }

    if directories:
        names = sorted({name for directory in directories
                        for name in os.listdir(directory) if name.endswith('.dot')})
        raw_identical, normalised_identical, missing = 0, 0, 0
        for name in names:
            paths = [os.path.join(directory, name) for directory in directories]
            if not all(os.path.exists(path) for path in paths):
                missing += 1
                continue
            if len({compare.file_digest(path) for path in paths}) == 1:
                raw_identical += 1
            if len({compare.file_digest(path, compare.normalise_dot)
                    for path in paths}) == 1:
                normalised_identical += 1
        verdict.update({
            'n_ag_dot_files': len(names),
            'ag_dot_identical_raw': raw_identical,
            'ag_dot_identical_normalised': normalised_identical,
            'ag_dot_missing_in_some_repeat': missing,
            'ag_dot_match_rate_raw': raw_identical / len(names) if names else None,
            'ag_dot_match_rate_normalised': (normalised_identical / len(names)
                                             if names else None),
        })
    return verdict


def _all_identical(paths):
    """
    Reports whether every path has the same bytes.

    @param paths: the files to compare
    @return: True, False, or None if there was nothing to compare
    """
    if len(paths) < 2:
        return None
    return len({compare.file_digest(path) for path in paths}) == 1
