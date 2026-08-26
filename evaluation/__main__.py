"""
Command line for the evaluation framework.

    python -m evaluation run   --dataset cptc-2017 --worktree ../SAGE-baseline
    python -m evaluation check --dataset cptc-2017 --worktree ../SAGE-baseline
    python -m evaluation report --dataset cptc-2017

`run` records a baseline; `check` re-runs and diffs against the stored record,
exiting non-zero on regression. The exit code is the point of `check`: it is what
makes the stored snapshot a regression reference rather than a document, and what
lets CI or a later contributor discover that they changed the pipeline's output
without meaning to.
"""
import argparse
import os
import shutil
import sys

from evaluation import collect, compare, perturbation, report, runner, schema

DATASET_PATHS = {
    'cptc-2017': ('alerts/cptc-2017', 'cptc'),
    'cptc-2018': ('alerts/cptc-2018', 'cptc'),
    'ccdc': ('alerts/ccdc', 'other'),
}

DEFAULT_BASELINE_DIR = 'baseline'
DEFAULT_RUN_ROOT = os.path.join('..', 'eval-runs')


def _dataset_paths(dataset, alerts_root):
    """
    Resolves a dataset key to its alerts directory and SAGE --dataset flag.

    @param dataset: a key of DATASET_PATHS
    @param alerts_root: the tree holding `alerts/`, which may differ from the
        worktree being measured -- the alert corpus is ~839 MB and identical at
        both commits, so it is not decompressed twice
    @return: (absolute_alerts_path, dataset_flag)
    """
    relative, flag = DATASET_PATHS[dataset]
    return os.path.abspath(os.path.join(alerts_root, relative)), flag


def _prepare(args):
    """
    Pins the IANA CSV, writes the shim, and captures the environment.

    @param args: parsed CLI arguments
    @return: (iana_record, shim_directory, environment_fingerprint)
    """
    run_root = os.path.abspath(args.run_root)
    iana = runner.snapshot_iana(os.path.join(run_root, 'pinned', 'iana-service-names.csv'))
    shim = runner.write_iana_shim(os.path.join(run_root, 'shim'), iana['path'])
    environment = runner.environment_fingerprint(args.worktree)
    return iana, shim, environment


def _run_reference(args, iana, shim, label='reference'):
    """
    Runs the single reference cell for a dataset and measures it.

    @param args: parsed CLI arguments
    @param iana: the pinned CSV record
    @param shim: the PYTHONPATH shim directory
    @param label: distinguishes the cell from the stored reference. A `check` must
        never write into the reference cell: it may be run against a different
        alert corpus (that is how a regression is demonstrated), and reusing the
        name overwrites the reference artifacts with the candidate's.
    @return: (cell_record, record_section)
    """
    dataset_path, flag = _dataset_paths(args.dataset, args.alerts_root)
    defaults = perturbation.DATASET_DEFAULTS[args.dataset]
    cell = {'name': '{}-{}'.format(args.dataset, label),
            'dataset_path': dataset_path, 'dataset_flag': flag,
            't': defaults['t'], 'w': defaults['w']}
    if args.timerange:
        cell['timerange'] = tuple(args.timerange)

    cell_record = runner.execute_cell(cell, args.worktree,
                                      os.path.join(os.path.abspath(args.run_root), 'cells'),
                                      iana, shim, force=args.force)
    if cell_record['exit_code'] != 0:
        raise SystemExit('Reference run failed with exit code {}. See {}/stdout.log'
                         .format(cell_record['exit_code'],
                                 os.path.join(args.run_root, 'cells', cell['name'])))
    return cell_record, collect.measure_cell(cell_record, dataset_path, flag)


def _repeats(args, iana, shim, dataset_path, flag):
    """
    Runs N identical repeats and summarises their variance and artifact match.

    @param args: parsed CLI arguments
    @param iana: the pinned CSV record
    @param shim: the PYTHONPATH shim directory
    @param dataset_path: the alerts directory
    @param flag: the SAGE --dataset flag
    @return: the record's 'repeats' section
    """
    defaults = perturbation.DATASET_DEFAULTS[args.dataset]
    cells_root = os.path.join(os.path.abspath(args.run_root), 'cells')

    records, sections = [], []
    for index in range(args.repeats):
        cell = {'name': '{}-repeat-{}'.format(args.dataset, index),
                'dataset_path': dataset_path, 'dataset_flag': flag,
                't': defaults['t'], 'w': defaults['w']}
        if args.timerange:
            cell['timerange'] = tuple(args.timerange)
        cell_record = runner.execute_cell(cell, args.worktree, cells_root, iana, shim,
                                          force=args.force)
        if cell_record['exit_code'] != 0:
            print('  repeat {} FAILED (exit {}), excluded from variance'
                  .format(index, cell_record['exit_code']), file=sys.stderr)
            continue
        records.append(cell_record)
        sections.append(collect.measure_cell(cell_record, dataset_path, flag))
        print('  repeat {}/{} done'.format(index + 1, args.repeats))

    if not sections:
        return {}
    return {'n': len(sections),
            'summary': collect.summarise_repeats(sections),
            'exact_match': collect.exact_match_across_repeats(records)}


def _perturbation_cells(args, iana, shim, reference_section, keep_corpora=False):
    """
    Runs the noise-injection grid and measures each cell's distortion.

    Perturbed alert corpora are written under the run root rather than over the
    originals, and each cell gets its own experiment name so no two
    configurations ever share an output directory. Each corpus is deleted once
    measured -- see the note at the call site.

    @param args: parsed CLI arguments
    @param iana: the pinned CSV record
    @param shim: the PYTHONPATH shim directory
    @param reference_section: the reference run, to measure distortion against
    @param keep_corpora: retain the perturbed datasets instead of deleting them
    @return: a list of perturbation cell results
    """
    source_path, flag = _dataset_paths(args.dataset, args.alerts_root)
    run_root = os.path.abspath(args.run_root)
    cells_root = os.path.join(run_root, 'cells')

    grid = perturbation.perturbation_grid(
        families=args.families or None,
        rates=args.rates or None,
        seeds=args.seeds or None)
    print('Perturbation grid: {} cells'.format(len(grid)))

    results = []
    for index, spec in enumerate(grid, start=1):
        name = '{}-{}-r{}-s{}'.format(args.dataset, spec['family'],
                                      str(spec['rate']).replace('.', ''), spec['seed'])
        corpus = os.path.join(run_root, 'perturbed', name, 'alerts')
        manifest = perturbation.perturb_dataset(source_path, corpus, spec['family'],
                                                spec['rate'], spec['seed'])

        cell = {'name': name, 'dataset_path': corpus, 'dataset_flag': flag,
                't': perturbation.DATASET_DEFAULTS[args.dataset]['t'],
                'w': perturbation.DATASET_DEFAULTS[args.dataset]['w']}
        if args.timerange:
            cell['timerange'] = tuple(args.timerange)

        try:
            cell_record = runner.execute_cell(cell, args.worktree, cells_root, iana, shim,
                                              force=args.force)
        except Exception as error:                          # noqa: BLE001
            print('  [{}/{}] {} FAILED: {}'.format(index, len(grid), name, error),
                  file=sys.stderr)
            results.append({'spec': spec, 'error': str(error)})
            continue

        if cell_record['exit_code'] != 0:
            results.append({'spec': spec, 'error': 'exit {}'.format(cell_record['exit_code'])})
            print('  [{}/{}] {} exited {}'.format(index, len(grid), name,
                                                  cell_record['exit_code']), file=sys.stderr)
            continue

        section = collect.measure_cell(cell_record, corpus, flag)
        results.append({
            'spec': spec,
            'manifest': {k: v for k, v in manifest.items() if k != 'per_file'},
            'metrics': section['attack_graphs']['aggregate'],
            'perplexity': section['perplexity']['training'].get('perplexity'),
            'distortion': _distortion(reference_section, section),
            'timing': {'wall_clock_seconds': section['timing']['wall_clock_seconds']},
        })

        # Discard the perturbed corpus once it has been measured. It is a full
        # copy of the dataset per cell -- ~27 GB across a 48-cell grid on
        # CPTC-2018 -- and it is exactly reproducible from (family, rate, seed),
        # so keeping it buys nothing. The cell's own artifacts and metrics are
        # already harvested, so resuming does not need it either.
        if not keep_corpora:
            shutil.rmtree(os.path.dirname(corpus), ignore_errors=True)

        print('  [{}/{}] {} ok'.format(index, len(grid), name))
    return results


def _sweep_cells(args, iana, shim, reference_section):
    """
    Runs the one-at-a-time `-t`/`-w` sweep and computes per-metric elasticity.

    @param args: parsed CLI arguments
    @param iana: the pinned CSV record
    @param shim: the PYTHONPATH shim directory
    @param reference_section: the reference run, to measure distortion against
    @return: a list of sweep cell results
    """
    dataset_path, flag = _dataset_paths(args.dataset, args.alerts_root)
    cells_root = os.path.join(os.path.abspath(args.run_root), 'cells')
    grid = perturbation.sweep_grid(args.dataset)
    print('Sweep grid: {} cells'.format(len(grid)))

    results = []
    for index, spec in enumerate(grid, start=1):
        name = '{}-sweep-{}{}'.format(args.dataset, spec['parameter'],
                                      str(spec['value']).replace('.', ''))
        cell = {'name': name, 'dataset_path': dataset_path, 'dataset_flag': flag,
                't': spec['t'], 'w': spec['w']}
        if args.timerange:
            cell['timerange'] = tuple(args.timerange)

        cell_record = runner.execute_cell(cell, args.worktree, cells_root, iana, shim,
                                          force=args.force)
        if cell_record['exit_code'] != 0:
            results.append({'spec': spec, 'error': 'exit {}'.format(cell_record['exit_code'])})
            continue

        section = collect.measure_cell(cell_record, dataset_path, flag)
        distortion = _distortion(reference_section, section)

        # Elasticity: relative change in the metric per relative change in the
        # parameter, so the paper can say which parameter the model is most
        # sensitive to rather than only that it is sensitive.
        parameter_change = ((spec['value'] - spec['baseline_value'])
                            / spec['baseline_value'] if spec['baseline_value'] else None)
        elasticities = {
            metric: compare.elasticity(delta.get('relative'), parameter_change)
            for metric, delta in distortion['metric_deltas'].items()}

        results.append({
            'spec': spec,
            'parameter_relative_change': parameter_change,
            'metrics': section['attack_graphs']['aggregate'],
            'perplexity': section['perplexity']['training'].get('perplexity'),
            'distortion': distortion,
            'elasticity': elasticities,
        })
        print('  [{}/{}] {} ok'.format(index, len(grid), name))
    return results


def _distortion(reference_section, candidate_section):
    """
    Measures how far a cell moved from the reference run.

    @param reference_section: the reference record section
    @param candidate_section: the cell's record section
    @return: a dict of distortion measures
    """
    reference = reference_section['attack_graphs']
    candidate = candidate_section['attack_graphs']

    reference_graphs = {(g['victim'], g['objective']) for g in reference['per_graph']}
    candidate_graphs = {(g['victim'], g['objective']) for g in candidate['per_graph']}

    return {
        'graph_jaccard': compare.jaccard(reference_graphs, candidate_graphs),
        'n_ags_gained': len(candidate_graphs - reference_graphs),
        'n_ags_lost': len(reference_graphs - candidate_graphs),
        'metric_deltas': compare.metric_deltas(reference['aggregate'],
                                               candidate['aggregate']),
    }


def command_run(args):
    """
    Records a baseline for one dataset.

    @param args: parsed CLI arguments
    @return: the process exit code
    """
    iana, shim, environment = _prepare(args)
    dataset_path, flag = _dataset_paths(args.dataset, args.alerts_root)

    print('Reference run for {}...'.format(args.dataset))
    cell_record, section = _run_reference(args, iana, shim)

    record = schema.new_record(args.dataset, cell_record['measured_commit'],
                               environment, iana)
    record['reference'] = section

    if section['alerts'].get('counter_agrees_with_sage') is False:
        schema.add_note(record,
                        'Alert counts DISAGREE: this package counted {} but SAGE reported {}. '
                        'Every alert-derived metric is suspect until reconciled.'
                        .format(section['alerts']['totals']['raw_alerts'],
                                section['alerts']['from_sage_stdout']['sage_read']))

    if args.timerange:
        schema.add_note(record, 'PARTIAL RUN: --timerange {} {} was applied, so this is not '
                                'a full-dataset baseline.'.format(*args.timerange))

    if args.heldout:
        print('Held-out perplexity (second FlexFringe run)...')
        record['reference']['perplexity']['heldout'] = collect.score_heldout(
            cell_record['artifacts'], args.worktree,
            os.path.join(os.path.abspath(args.run_root), 'heldout', args.dataset))
        heldout = record['reference']['perplexity']['heldout']
        if heldout.get('perplexity') is None:
            schema.add_note(record, 'Held-out perplexity absent: {}'
                                    .format(heldout.get('absent_because')))
        elif (heldout.get('unresolved_fraction') or 0) > 0.2:
            schema.add_note(
                record,
                'Held-out perplexity rests heavily on the unresolved-step policy: {:.0%} of '
                'scored outcomes fell off the model entirely and took the uniform fallback. '
                'It is NOT a like-for-like comparison against the training figure.'
                .format(heldout['unresolved_fraction']))

    if args.repeats:
        print('Repeat runs ({} x)...'.format(args.repeats))
        record['repeats'] = _repeats(args, iana, shim, dataset_path, flag)

    if args.perturb:
        print('Perturbation runs...')
        record['perturbations'] = _perturbation_cells(
            args, iana, shim, section, keep_corpora=args.keep_corpora)

    if args.sweep:
        print('Sensitivity sweep...')
        record['sweeps'] = _sweep_cells(args, iana, shim, section)

    os.makedirs(args.baseline_dir, exist_ok=True)
    json_path = os.path.join(args.baseline_dir, 'metrics-{}.json'.format(args.dataset))
    schema.save(record, json_path)
    print('Wrote {}'.format(json_path))

    if args.markdown:
        with open(args.markdown, 'w', encoding='utf-8') as handle:
            handle.write(report.render(record))
        print('Wrote {}'.format(args.markdown))
    return 0


def command_check(args):
    """
    Re-runs a dataset and diffs it against the stored baseline.

    @param args: parsed CLI arguments
    @return: 0 if the run matches the baseline, 1 otherwise
    """
    json_path = os.path.join(args.baseline_dir, 'metrics-{}.json'.format(args.dataset))
    if not os.path.exists(json_path):
        raise SystemExit('No stored baseline at {}. Run `python -m evaluation run '
                         '--dataset {}` first.'.format(json_path, args.dataset))

    baseline = schema.load(json_path)
    iana, shim, environment = _prepare(args)

    if baseline.get('iana', {}).get('sha256') != iana['sha256']:
        print('WARNING: the pinned IANA CSV differs from the one used for the baseline '
              '({} vs {}). Structural differences may be caused by that, not by a code '
              'change.'.format(baseline.get('iana', {}).get('sha256'), iana['sha256']),
              file=sys.stderr)

    args.force = True  # A check must actually re-run, never reuse a cached cell
    cell_record, section = _run_reference(args, iana, shim, label='check')
    candidate = schema.new_record(args.dataset, cell_record['measured_commit'],
                                  environment, iana)
    candidate['reference'] = section

    result = schema.check_regression(baseline, candidate)
    print(report.render_check(result))
    return 0 if result['passed'] else 1


def command_report(args):
    """
    Re-renders the outputs from stored records, without re-running anything.

    Every output is derived from the JSON, so a metric definition can be
    corrected, a chart restyled or a figure re-cut without spending the compute
    again -- which is why the records keep per-graph and per-cell detail rather
    than only summaries.

    @param args: parsed CLI arguments
    @return: the process exit code
    """
    json_path = os.path.join(args.baseline_dir, 'metrics-{}.json'.format(args.dataset))
    if not os.path.exists(json_path):
        raise SystemExit('No stored baseline at {}.'.format(json_path))

    document = report.render(schema.load(json_path))
    if args.markdown:
        with open(args.markdown, 'w', encoding='utf-8') as handle:
            handle.write(document)
        print('Wrote {}'.format(args.markdown))
    elif not (args.figures or args.dashboard):
        print(document)

    if args.figures:
        from evaluation import figures
        for name, paths in sorted(figures.render_all(args.baseline_dir,
                                                     args.figures).items()):
            print('  {:28s} {}'.format(
                name, 'skipped (no data)' if not paths else os.path.basename(paths[0])))
        print('Wrote figures to {}'.format(args.figures))

    if args.dashboard:
        from evaluation import dashboard
        # Scoped to the requested dataset: the page renders one record, so
        # handing it every stored dataset would silently display only the first.
        dashboard.write(args.baseline_dir, args.dashboard, datasets=[args.dataset])
        print('Wrote {}'.format(args.dashboard))
    return 0


def build_parser():
    """
    Builds the argument parser.

    @return: the configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog='python -m evaluation',
        description='Record and check baseline evaluation metrics for SAGE.')
    parser.add_argument('command', choices=['run', 'check', 'report'])
    parser.add_argument('--dataset', required=True, choices=sorted(DATASET_PATHS))
    parser.add_argument('--worktree', default=os.path.join('..', 'SAGE-baseline'),
                        help='the SAGE tree to measure (default: ../SAGE-baseline)')
    parser.add_argument('--alerts-root', default='.',
                        help='the tree holding alerts/ (default: the current tree, so the '
                             '839 MB corpus is not decompressed twice)')
    parser.add_argument('--run-root', default=DEFAULT_RUN_ROOT,
                        help='where run cells and the pinned IANA CSV live')
    parser.add_argument('--baseline-dir', default=DEFAULT_BASELINE_DIR,
                        help='where metrics-<dataset>.json is stored')
    parser.add_argument('--markdown', default=None, help='also write a Markdown report here')
    parser.add_argument('--figures', default=None, metavar='DIR',
                        help='render publication figures (PDF + PNG) into this directory')
    parser.add_argument('--dashboard', default=None, metavar='HTML',
                        help='render the self-contained HTML review dashboard here')
    parser.add_argument('--repeats', type=int, default=0,
                        help='number of identical repeat runs for variance (spec: 5)')
    parser.add_argument('--timerange', type=int, nargs=2, default=None,
                        metavar=('START', 'END'),
                        help='pass --timerange to SAGE; marks the record as partial')
    parser.add_argument('--force', action='store_true',
                        help='re-run cells that are already complete')
    parser.add_argument('--heldout', action='store_true',
                        help='also score held-out perplexity (needs a 2nd FlexFringe run)')
    parser.add_argument('--perturb', action='store_true',
                        help='run the noise-injection grid (expensive: families x rates x seeds)')
    parser.add_argument('--sweep', action='store_true',
                        help='run the one-at-a-time -t/-w sensitivity sweep')
    parser.add_argument('--keep-corpora', action='store_true',
                        help='keep perturbed alert copies (default: delete once measured; '
                             'they are ~27 GB on a full CPTC-2018 grid and are exactly '
                             'reproducible from family/rate/seed)')
    # Grid overrides, so CCDC can run a reduced matrix without editing code.
    parser.add_argument('--families', nargs='*', default=None,
                        choices=perturbation.FAMILIES,
                        help='limit the perturbation families (default: all four)')
    parser.add_argument('--rates', nargs='*', type=float, default=None,
                        help='limit the perturbation rates (default: 0.01 0.05 0.10 0.20)')
    parser.add_argument('--seeds', nargs='*', type=int, default=None,
                        help='limit the perturbation seeds (default: 1 2 3)')
    return parser


def main(argv=None):
    """
    Entry point.

    @param argv: the argument list, or None for sys.argv
    @return: the process exit code
    """
    args = build_parser().parse_args(argv)
    return {'run': command_run, 'check': command_check, 'report': command_report}[
        args.command](args)


if __name__ == '__main__':
    sys.exit(main())
