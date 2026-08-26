"""
Renders a result record as human-readable Markdown.

The JSON record is the machine-readable reference; this is the document a person
reads. It exists to satisfy a specific acceptance criterion: a second person must
be able to reproduce the headline table from the document alone, on a clean
checkout. That is why the reproduction command and the environment block are
rendered as prominently as the numbers, and why every metric's formula is printed
rather than assumed -- a number without its definition cannot be reproduced, only
re-obtained by luck.
"""
from evaluation import alerts as alerts_module
from evaluation import dot_metrics


def _fmt(value, places=3):
    """
    Formats a value for a Markdown table, distinguishing absent from zero.

    @param value: the value
    @param places: decimal places for floats
    @return: the formatted string
    """
    if value is None:
        return '--'
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, float):
        return '{:,.{}f}'.format(value, places)
    if isinstance(value, int):
        return '{:,}'.format(value)
    return str(value)


def headline_table(record):
    """
    Renders the headline metric table for one dataset.

    @param record: a result record
    @return: Markdown lines
    """
    reference = record.get('reference') or {}
    aggregate = reference.get('attack_graphs', {}).get('aggregate', {})
    totals = reference.get('alerts', {}).get('totals', {})
    compression = reference.get('compression', {})
    timing = reference.get('timing', {})
    training = reference.get('perplexity', {}).get('training', {})
    heldout = reference.get('perplexity', {}).get('heldout', {})

    primary = compression.get('primary')
    rows = [
        ('Raw records', _fmt(totals.get('raw_records'))),
        ('Raw alerts (post-filter)', _fmt(totals.get('raw_alerts'))),
        ('Post-dedup alerts', _fmt(compression.get('inputs', {}).get('post_dedup_alerts'))),
        ('Attack graphs', _fmt(aggregate.get('n_attack_graphs'))),
        ('Victims', _fmt(aggregate.get('n_victims'))),
        ('Objectives', _fmt(aggregate.get('n_objectives'))),
        ('Total AG nodes', _fmt(aggregate.get('total_nodes'))),
        ('Unique AG nodes', _fmt(aggregate.get('unique_nodes'))),
        ('Total AG edges', _fmt(aggregate.get('total_edges'))),
        ('Compression ({})'.format(primary), _fmt(compression.get(primary), 1)),
        ('Perplexity (training)', _fmt(training.get('perplexity'))),
        ('Perplexity (held-out)', _fmt(heldout.get('perplexity'))),
        ('Wall clock (s)', _fmt(timing.get('wall_clock_seconds'), 1)),
        ('Throughput (records/s)', _fmt(timing.get('alert_throughput'), 0)),
    ]

    lines = ['| Metric | Value |', '|---|---:|']
    lines += ['| {} | {} |'.format(name, value) for name, value in rows]
    return lines


def distribution_table(record):
    """
    Renders the per-graph structural metric distribution.

    Reported as a distribution rather than a single mean because the dataset-level
    aggregate hides that AG sizes span an order of magnitude.

    @param record: a result record
    @return: Markdown lines
    """
    distribution = (record.get('reference', {})
                    .get('attack_graphs', {}).get('distribution', {}))
    if not distribution:
        return ['_No per-graph distribution recorded._']

    lines = ['| Metric | n | min | median | mean | max |', '|---|---:|---:|---:|---:|---:|']
    for name, stats in distribution.items():
        lines.append('| {} | {} | {} | {} | {} | {} |'.format(
            name, _fmt(stats.get('n')), _fmt(stats.get('min')), _fmt(stats.get('median')),
            _fmt(stats.get('mean')), _fmt(stats.get('max'))))
    return lines


def environment_block(record):
    """
    Renders the environment fingerprint.

    Runtime figures are only comparable within one fingerprint, so this is part of
    the result, not front matter.

    @param record: a result record
    @return: Markdown lines
    """
    environment = record.get('environment') or {}
    interesting = ['os', 'processor', 'cpu_count', 'total_ram_bytes', 'python_version',
                   'graphviz_version', 'glibc_version', 'kernel', 'wsl_kernel',
                   'runs_flexfringe_via', 'flexfringe_sha256', 'flexfringe_ini_sha256']
    lines = ['| Property | Value |', '|---|---|']
    for key in interesting:
        if environment.get(key) is not None:
            lines.append('| {} | `{}` |'.format(key, environment[key]))

    iana = record.get('iana') or {}
    if iana:
        lines.append('| iana_csv_sha256 | `{}` |'.format(iana.get('sha256')))
        lines.append('| iana_pinned_at | `{}` |'.format(iana.get('pinned_at')))
    return lines


def variance_section(record):
    """
    Renders the repeat-run variance and the determinism verdict.

    The verdict matters more than the numbers: if the pipeline is not
    deterministic, every downstream regression reference needs tolerance bands
    rather than fixed values, and that has to be stated plainly rather than left
    for a reader to infer from a stdev column.

    @param record: a result record
    @return: Markdown lines
    """
    repeats = record.get('repeats') or {}
    if not repeats:
        return ['_No repeat runs recorded, so determinism is unverified. '
                'Until repeats are run, treat the reference values as unconfirmed._']

    lines = []
    match = repeats.get('exact_match') or {}
    if match:
        raw = match.get('ag_dot_match_rate_raw')
        normalised = match.get('ag_dot_match_rate_normalised')
        lines += [
            '**Exact-artifact match across {} repeats**'.format(match.get('n_repeats')),
            '',
            '| Artifact | Identical |', '|---|---|',
            '| Trace file (`.txt`) | {} |'.format(_fmt(match.get('traces_identical'))),
            '| Main model JSON | {} |'.format(_fmt(match.get('main_model_identical'))),
            '| AG `.dot` (raw bytes) | {} of {} |'.format(
                _fmt(match.get('ag_dot_identical_raw')), _fmt(match.get('n_ag_dot_files'))),
            '| AG `.dot` (tooltip-normalised) | {} of {} |'.format(
                _fmt(match.get('ag_dot_identical_normalised')),
                _fmt(match.get('n_ag_dot_files'))),
            '',
        ]
        if raw is not None and normalised is not None:
            if normalised == 1.0 and raw < 1.0:
                lines += [
                    '> **Verdict: deterministic modulo tooltip ordering.** The `.dot` files '
                    'differ byte-for-byte but are identical once tooltip signature order is '
                    'normalised. At `baseline-v1` the tooltip join is unsorted over a set and '
                    'Python randomises string hashing per process, so this is a formatting '
                    'artefact, not pipeline instability. Fixed structural values are safe as '
                    'a regression reference.', '']
            elif normalised == 1.0 and raw == 1.0:
                lines += ['> **Verdict: fully deterministic**, byte-for-byte, across repeats.',
                          '']
            else:
                lines += [
                    '> **Verdict: NOT deterministic.** Artifacts differ even after '
                    'normalisation. Every downstream regression reference derived from this '
                    'baseline needs tolerance bands rather than fixed numbers, and the '
                    'tolerances in `schema.TOLERANCES` must be widened accordingly.', '']

    summary = repeats.get('summary') or {}
    if summary:
        lines += ['| Metric | min | median | max | stdev |', '|---|---:|---:|---:|---:|']
        for name, stats in sorted(summary.items()):
            lines.append('| {} | {} | {} | {} | {} |'.format(
                name, _fmt(stats.get('min')), _fmt(stats.get('median')),
                _fmt(stats.get('max')), _fmt(stats.get('stdev'))))
    return lines


def definitions_section():
    """
    Renders every metric formula.

    Printed in full because the paper leaves several metrics underspecified and
    one (density) entirely undefined, so the formula actually used is the only
    reliable statement of what a recorded number means.

    @return: Markdown lines
    """
    lines = ['Every formula actually used, verbatim from the code that computed it.', '']
    for name, formula in sorted(dot_metrics.FORMULAS.items()):
        lines += ['**`{}`**'.format(name), '', '> {}'.format(formula), '']
    for name, formula in sorted(alerts_module.COMPRESSION_FORMULAS.items()):
        lines += ['**`{}`**'.format(name), '', '> {}'.format(formula), '']
    lines += ['**Edge bases**', '']
    for name, meaning in sorted(dot_metrics.EDGE_BASES.items()):
        lines.append('- `{}` -- {}'.format(name, meaning))
    return lines


def perplexity_section(record):
    """
    Renders the perplexity definitions and diagnostics.

    @param record: a result record
    @return: Markdown lines
    """
    training = (record.get('reference', {}).get('perplexity', {}).get('training') or {})
    if not training or training.get('perplexity') is None:
        return ['_No perplexity recorded: {}_'.format(training.get('absent_because', 'unknown'))]

    resolved = training.get('resolved_by_model', {})
    lines = [
        '| Property | Value |', '|---|---|',
        '| Training perplexity | {} |'.format(_fmt(training.get('perplexity'))),
        '| Scored outcomes | {} |'.format(_fmt(training.get('n_scored_outcomes'))),
        '| Symbols | {} |'.format(_fmt(training.get('n_symbols'))),
        '| Traces | {} |'.format(_fmt(training.get('n_traces'))),
        '| Alphabet size | {} |'.format(_fmt(training.get('alphabet_size'))),
        '| Smoothing alpha | {} |'.format(_fmt(training.get('alpha'))),
        '| End-of-trace scored | {} |'.format(_fmt(training.get('scores_end_of_trace'))),
        '| Probability source | `{}` |'.format(training.get('prob_source')),
        '| Unresolved events | {} |'.format(_fmt(training.get('unresolved_events'))),
        '| Out-of-vocabulary events | {} |'.format(_fmt(training.get('oov_events'))),
        '| Steps resolved via main model | {} |'.format(_fmt(resolved.get('main'))),
        '| Steps resolved via sinks model | {} |'.format(_fmt(resolved.get('sinks'))),
        '',
        '> {}'.format(training.get('formula')),
        '',
        '> {}'.format(training.get('prob_formula')),
        '',
        '> Unresolved: {}'.format(training.get('unresolved_policy')),
        '',
        '> Out-of-vocabulary: {}'.format(training.get('oov_policy')),
    ]
    return lines


def _reproduction_command(argv):
    """
    Renders a recorded argv as a command another person can actually run.

    The stored argv begins with `sys.executable`, an absolute path to the
    interpreter on the machine that ran it (`C:\\Python313\\python.exe`). Printing
    that verbatim would defeat the point of the document, which is that a second
    person can reproduce the table on a clean checkout, so it is rendered as a
    plain `python`. The exact recorded argv stays in the JSON record.

    @param argv: the recorded argv list
    @return: the command string
    """
    if not argv:
        return ''
    parts = ['python'] + [str(part) for part in argv[1:]]
    return ' '.join(parts)


def render(record):
    """
    Renders a complete Markdown report for one dataset.

    @param record: a result record
    @return: the Markdown document as a string
    """
    reference = record.get('reference') or {}
    command = _reproduction_command(reference.get('argv') or [])

    lines = [
        '# Baseline metrics: `{}`'.format(record.get('dataset')),
        '',
        '- **Schema version:** {}'.format(record.get('schema_version')),
        '- **Measured commit:** `{}`'.format(record.get('measured_commit')),
        '- **Recorded:** {}'.format(record.get('created_at')),
        '- **Host:** `{}`'.format(record.get('host')),
        '',
        '## Reproduction',
        '',
        'Run from the SAGE tree at the commit above, with `PYTHONHASHSEED=0`:',
        '',
        '```bash',
        'PYTHONHASHSEED=0 {}'.format(command or '# no command recorded'),
        '```',
        '',
        'The IANA port-service CSV is fetched live by SAGE and changes AG structure when '
        'it changes upstream, so it is pinned for this baseline; see the digest in the '
        'environment block below and `evaluation/runner.py` for how the pinned copy is served.',
        '',
        '## Headline metrics',
        '',
    ]
    lines += headline_table(record)
    lines += ['', '## Per-graph structural distribution', '']
    lines += distribution_table(record)
    lines += ['', '## Perplexity', '']
    lines += perplexity_section(record)
    lines += ['', '## Output variance and determinism', '']
    lines += variance_section(record)
    lines += ['', '## Metric definitions', '']
    lines += definitions_section()
    lines += ['', '## Environment', '']
    lines += environment_block(record)

    notes = record.get('notes') or []
    if notes:
        lines += ['', '## Notes and caveats', '']
        lines += ['- {}'.format(note) for note in notes]

    return '\n'.join(lines) + '\n'


def render_check(result):
    """
    Renders the outcome of a regression check as plain text for a terminal.

    @param result: the result from `schema.check_regression`
    @return: the report as a string
    """
    lines = ['PASS' if result['passed'] else 'FAIL',
             '{} metrics compared, {} failing'.format(result['n_compared'],
                                                      len(result['failures']))]
    if result.get('schema_warning'):
        lines.append('WARNING: ' + result['schema_warning'])

    for finding in result['findings']:
        if finding['status'] in ('ok',):
            continue
        lines.append('  [{:13s}] {:24s} expected={} actual={} rel={}'.format(
            finding['status'], finding['metric'], _fmt(finding.get('expected')),
            _fmt(finding.get('actual')),
            _fmt(finding.get('relative'), 6) if finding.get('relative') is not None else '--'))

    if result.get('new_metrics'):
        lines.append('  new metrics not in baseline: {}'.format(
            ', '.join(result['new_metrics'])))
    return '\n'.join(lines)
