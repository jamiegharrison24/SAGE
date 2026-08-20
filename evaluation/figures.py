"""
Renders publication figures from stored baseline records.

Reads `baseline/metrics-<dataset>.json` and writes vector PDF (for the paper) plus
PNG (for slides and review). Nothing here re-runs SAGE, so a figure can be
restyled, corrected or re-cut without spending compute again -- which is the whole
reason the records store per-graph and per-cell detail rather than just summaries.

Sizing targets an IEEE two-column layout: `COLUMN_WIDTH` fits one column,
`PAGE_WIDTH` spans both.

Colour follows a validated categorical palette (see the palette table below).
Slots are assigned in fixed order and never cycled. Two consequences are wired in
deliberately:

- Every series is **direct-labelled**, not identified by legend colour alone. Two
  of the four slots fall below 3:1 contrast on a light surface, and direct labels
  are the required relief. It also makes the figures readable in greyscale print,
  which a paper needs anyway.
- Stage colours in the runtime figure fold to five groups rather than colouring
  all ten banners, because a categorical palette past its validated slot count
  stops being distinguishable.
"""
import json
import os

import matplotlib
matplotlib.use('Agg')                      # Headless: no display needed
import matplotlib.pyplot as plt            # noqa: E402

# IEEE two-column geometry, in inches.
COLUMN_WIDTH = 3.5
PAGE_WIDTH = 7.16

# Validated categorical palette, light surface. Fixed order, never cycled.
SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']
INK = '#0b0b0b'
INK_SECONDARY = '#52514e'
MUTED = '#898781'
GRID = '#e1e0d9'
BASELINE_RULE = '#c3c2b7'
SURFACE = '#fcfcfb'

# Human labels for the perturbation families, in the order they take colour slots.
FAMILY_LABELS = {
    'false_positives': 'False positives',
    'duplicates': 'Duplicate bursts',
    'missing_alerts': 'Dropped alerts',
    'missing_episodes': 'Dropped episodes',
}

# The ten stage banners fold into five groups: ten categorical colours would not be
# distinguishable, and the sub-second stages are not worth a slot each.
STAGE_GROUPS = [
    ('Reading alerts', ['Reading alerts']),
    ('Episode building', ['Converting to episodes', 'Converting to episode sequences',
                          'Breaking into sub-sequences and generating traces']),
    ('Learning S-PDFA', ['Learning S-PDFA']),
    ('Rendering AGs', ['Making alert-driven AGs']),
    ('Other', None),                        # Everything not claimed above
]


def _style(axis, ylabel=None, xlabel=None, title=None):
    """
    Applies the common chart chrome: recessive grid, no box, muted ticks.

    @param axis: the matplotlib axis
    @param ylabel: optional y label
    @param xlabel: optional x label
    @param title: optional title
    """
    axis.set_facecolor(SURFACE)
    for side in ('top', 'right'):
        axis.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        axis.spines[side].set_color(BASELINE_RULE)
        axis.spines[side].set_linewidth(0.8)
    axis.tick_params(colors=MUTED, labelsize=7, length=3, width=0.8)
    for label in axis.get_xticklabels() + axis.get_yticklabels():
        label.set_color(INK_SECONDARY)
    axis.grid(True, axis='y', color=GRID, linewidth=0.6, zorder=0)
    axis.set_axisbelow(True)
    if ylabel:
        axis.set_ylabel(ylabel, fontsize=8, color=INK_SECONDARY)
    if xlabel:
        axis.set_xlabel(xlabel, fontsize=8, color=INK_SECONDARY)
    if title:
        axis.set_title(title, fontsize=9, color=INK, loc='left', pad=8)


def _save(figure, output_directory, stem):
    """
    Writes a figure as both vector PDF and raster PNG.

    @param figure: the matplotlib figure
    @param output_directory: where to write
    @param stem: the filename stem
    @return: the list of written paths
    """
    os.makedirs(output_directory, exist_ok=True)
    written = []
    for extension in ('pdf', 'png'):
        path = os.path.join(output_directory, '{}.{}'.format(stem, extension))
        figure.savefig(path, dpi=300, bbox_inches='tight', facecolor=SURFACE)
        written.append(path)
    plt.close(figure)
    return written


def robustness_figure(record, output_directory):
    """
    Plots graph distortion against noise rate, one line per perturbation family.

    The headline robustness figure: it answers, in one panel, how far the attack
    graphs move as the alert stream degrades. The y axis is graph Jaccard against
    the reference run, so 1.0 is "identical set of attack graphs" and lower is more
    distorted. Seeds are shown as a min-max band rather than averaged away, since
    the spread across seeds is itself evidence about stability.

    @param record: a loaded result record
    @param output_directory: where to write the figure
    @return: the written paths, or None if the record has no perturbation cells
    """
    cells = [c for c in record.get('perturbations') or [] if 'distortion' in c]
    if not cells:
        return None

    by_family = {}
    for cell in cells:
        spec = cell['spec']
        by_family.setdefault(spec['family'], {}).setdefault(spec['rate'], []).append(
            cell['distortion']['graph_jaccard'])

    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 2.6))
    _style(axis, ylabel='Graph Jaccard vs reference', xlabel='Noise rate')

    for slot, family in enumerate(FAMILY_LABELS):
        if family not in by_family:
            continue
        colour = SERIES[slot % len(SERIES)]
        rates = sorted(by_family[family])
        medians = [sorted(by_family[family][r])[len(by_family[family][r]) // 2]
                   for r in rates]
        lows = [min(by_family[family][r]) for r in rates]
        highs = [max(by_family[family][r]) for r in rates]

        axis.fill_between(rates, lows, highs, color=colour, alpha=0.15, linewidth=0)
        axis.plot(rates, medians, color=colour, linewidth=2, marker='o',
                  markersize=4, markeredgecolor=SURFACE, markeredgewidth=1,
                  label=FAMILY_LABELS[family], zorder=3)
        # Direct label at the line end: identity must never be colour-alone.
        axis.annotate(FAMILY_LABELS[family], (rates[-1], medians[-1]),
                      xytext=(4, 0), textcoords='offset points', fontsize=7,
                      color=INK_SECONDARY, va='center')

    axis.set_ylim(0, 1.05)
    axis.set_xlim(0, max(r for f in by_family.values() for r in f) * 1.45)
    axis.set_xticks(sorted({r for f in by_family.values() for r in f}))
    axis.set_xticklabels(['{:.0%}'.format(r)
                          for r in sorted({r for f in by_family.values() for r in f})])
    return _save(figure, output_directory, 'fig-robustness-{}'.format(record['dataset']))


def sensitivity_figure(record, output_directory):
    """
    Plots per-metric elasticity for each swept parameter.

    Elasticity is the relative change in a metric per relative change in the
    parameter, so a bar near zero means the parameter does not move that metric at
    all -- which is the interesting result if it holds.

    @param record: a loaded result record
    @param output_directory: where to write the figure
    @return: the written paths, or None if the record has no sweep cells
    """
    cells = [c for c in record.get('sweeps') or [] if 'elasticity' in c]
    if not cells:
        return None

    metrics = ['n_attack_graphs', 'total_nodes', 'total_edges', 'unique_nodes']
    labels = ['Attack graphs', 'Nodes', 'Edges', 'Unique nodes']

    by_parameter = {}
    for cell in cells:
        values = by_parameter.setdefault(cell['spec']['parameter'], {})
        for metric in metrics:
            value = cell['elasticity'].get(metric)
            if value is not None:
                values.setdefault(metric, []).append(abs(value))

    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 2.4))
    _style(axis, xlabel='|elasticity|  (mean over swept values)')

    positions = range(len(metrics))
    height = 0.36
    for slot, (parameter, values) in enumerate(sorted(by_parameter.items())):
        colour = SERIES[slot % len(SERIES)]
        means = [(sum(values.get(m, [0])) / len(values.get(m, [0]))) for m in metrics]
        offsets = [p + (slot - 0.5) * height for p in positions]
        axis.barh(offsets, means, height=height * 0.92, color=colour,
                  label='-{}'.format(parameter), zorder=3)
        # Direct value labels: two of the palette slots are sub-3:1 on a light
        # surface, and these double as the greyscale-print fallback.
        for offset, value in zip(offsets, means):
            axis.annotate('{:.2f}'.format(value), (value, offset), xytext=(3, 0),
                          textcoords='offset points', fontsize=6.5,
                          color=INK_SECONDARY, va='center')

    axis.set_yticks(list(positions))
    axis.set_yticklabels(labels, fontsize=7.5)
    axis.grid(True, axis='x', color=GRID, linewidth=0.6)
    axis.grid(False, axis='y')
    axis.invert_yaxis()
    legend = axis.legend(fontsize=7, frameon=False, loc='lower right')
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)
    return _save(figure, output_directory, 'fig-sensitivity-{}'.format(record['dataset']))


def structure_figure(record, output_directory):
    """
    Plots the per-attack-graph distribution of the structural metrics.

    Shown as a distribution rather than a dataset-level mean because attack graph
    sizes span an order of magnitude, and a single mean hides that entirely.

    @param record: a loaded result record
    @param output_directory: where to write the figure
    @return: the written paths, or None if the record has no per-graph detail
    """
    graphs = (record.get('reference', {})
              .get('attack_graphs', {}).get('per_graph') or [])
    if not graphs:
        return None

    metrics = ['branching_factor', 'path_linearity', 'reachability_density', 'density']
    labels = ['Branching\nfactor', 'Path\nlinearity', 'Reachability\ndensity',
              'Edge\ndensity']
    series = [[g[m] for g in graphs if g.get(m) is not None] for m in metrics]

    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 2.4))
    _style(axis, ylabel='Value', title=None)

    box = axis.boxplot(series, patch_artist=True, widths=0.5, showfliers=True,
                       flierprops={'marker': 'o', 'markersize': 2.5,
                                   'markerfacecolor': MUTED, 'markeredgecolor': 'none',
                                   'alpha': 0.5},
                       medianprops={'color': SURFACE, 'linewidth': 1.5},
                       whiskerprops={'color': BASELINE_RULE, 'linewidth': 1},
                       capprops={'color': BASELINE_RULE, 'linewidth': 1})
    for slot, patch in enumerate(box['boxes']):
        patch.set_facecolor(SERIES[slot % len(SERIES)])
        patch.set_edgecolor(SURFACE)
        patch.set_linewidth(1)

    axis.set_xticklabels(labels, fontsize=7)
    axis.set_xlabel('n = {} attack graphs'.format(len(graphs)), fontsize=7.5,
                    color=MUTED)
    return _save(figure, output_directory, 'fig-structure-{}'.format(record['dataset']))


def runtime_figure(records, output_directory):
    """
    Plots per-stage runtime for each dataset as a stacked bar.

    Stages are folded into five groups (see STAGE_GROUPS) so the colour count stays
    inside the validated palette.

    @param records: the loaded records, one per dataset
    @param output_directory: where to write the figure
    @return: the written paths, or None if no record has stage timings
    """
    usable = [r for r in records if (r.get('reference', {})
                                     .get('timing', {}).get('stages'))]
    if not usable:
        return None

    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 2.4))
    _style(axis, ylabel='Seconds')

    claimed = {name for _, names in STAGE_GROUPS if names for name in names}
    positions = range(len(usable))
    bottoms = [0.0] * len(usable)

    for slot, (group_label, names) in enumerate(STAGE_GROUPS):
        values = []
        for record in usable:
            stages = record['reference']['timing']['stages']
            if names is None:
                total = sum(s['seconds'] for s in stages if s['stage'] not in claimed)
            else:
                total = sum(s['seconds'] for s in stages if s['stage'] in names)
            values.append(total)

        colour = SERIES[slot % len(SERIES)] if slot < len(SERIES) else MUTED
        axis.bar(list(positions), values, bottom=bottoms, width=0.55, color=colour,
                 label=group_label, zorder=3, edgecolor=SURFACE, linewidth=1.5)
        bottoms = [b + v for b, v in zip(bottoms, values)]

    axis.set_xticks(list(positions))
    axis.set_xticklabels([r['dataset'] for r in usable], fontsize=7.5)
    legend = axis.legend(fontsize=6.5, frameon=False, loc='upper left',
                         bbox_to_anchor=(1.01, 1.0))
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)
    return _save(figure, output_directory, 'fig-runtime')


def render_all(baseline_directory, output_directory, datasets=None):
    """
    Renders every figure the stored records can support.

    Figures whose inputs are absent (no perturbation cells yet, no sweep cells) are
    skipped and reported, rather than emitted empty.

    @param baseline_directory: the directory holding metrics-<dataset>.json
    @param output_directory: where to write figures
    @param datasets: dataset keys to include, or None for whatever is present
    @return: a dict of figure name -> written paths (or None where skipped)
    """
    if datasets is None:
        datasets = sorted(
            name[len('metrics-'):-len('.json')]
            for name in os.listdir(baseline_directory)
            if name.startswith('metrics-') and name.endswith('.json'))

    records = []
    for dataset in datasets:
        path = os.path.join(baseline_directory, 'metrics-{}.json'.format(dataset))
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as handle:
                records.append(json.load(handle))

    written = {}
    for record in records:
        dataset = record['dataset']
        written['robustness-' + dataset] = robustness_figure(record, output_directory)
        written['sensitivity-' + dataset] = sensitivity_figure(record, output_directory)
        written['structure-' + dataset] = structure_figure(record, output_directory)
    written['runtime'] = runtime_figure(records, output_directory)
    return written


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Render baseline figures.')
    parser.add_argument('--baseline-dir', default='baseline')
    parser.add_argument('--output-dir', default='figures')
    arguments = parser.parse_args()

    for name, paths in sorted(render_all(arguments.baseline_dir,
                                         arguments.output_dir).items()):
        print('{:28s} {}'.format(name, 'skipped (no data)' if not paths
                                 else os.path.basename(paths[0])))
