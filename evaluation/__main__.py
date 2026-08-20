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
import sys

from evaluation import collect, perturbation, report, runner, schema

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


def _run_reference(args, iana, shim):
    """
    Runs the single reference cell for a dataset and measures it.

    @param args: parsed CLI arguments
    @param iana: the pinned CSV record
    @param shim: the PYTHONPATH shim directory
    @return: (cell_record, record_section)
    """
    dataset_path, flag = _dataset_paths(args.dataset, args.alerts_root)
    defaults = perturbation.DATASET_DEFAULTS[args.dataset]
    cell = {'name': '{}-reference'.format(args.dataset),
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

    if args.repeats:
        print('Repeat runs ({} x)...'.format(args.repeats))
        record['repeats'] = _repeats(args, iana, shim, dataset_path, flag)

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
    cell_record, section = _run_reference(args, iana, shim)
    candidate = schema.new_record(args.dataset, cell_record['measured_commit'],
                                  environment, iana)
    candidate['reference'] = section

    result = schema.check_regression(baseline, candidate)
    print(report.render_check(result))
    return 0 if result['passed'] else 1


def command_report(args):
    """
    Re-renders the Markdown document from a stored record, without re-running.

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
    else:
        print(document)
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
    parser.add_argument('--repeats', type=int, default=0,
                        help='number of identical repeat runs for variance (spec: 5)')
    parser.add_argument('--timerange', type=int, nargs=2, default=None,
                        metavar=('START', 'END'),
                        help='pass --timerange to SAGE; marks the record as partial')
    parser.add_argument('--force', action='store_true',
                        help='re-run cells that are already complete')
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
