"""
Generates a self-contained HTML comparison of taxonomy/severity arms.

`evaluation/dashboard.py` answers "is this run healthy" for one pipeline
configuration across datasets. This answers a different question -- "what
changed between configurations" -- and the two do not collapse into one page:
the baseline dashboard's panels (perturbation, sweeps, per-graph scatter)
describe a single arm in depth, where a comparison needs the same few numbers
side by side with a baseline delta.

Reads the layout the severity-sensitivity runner writes:

    <root>/<arm>/metrics-<dataset>.json     the measured record
    <root>/<arm>/variant.json               which severity table produced it

The provenance panel is not decoration. Every arm records the same commit SHA,
because the thing that differs between them is a generated, gitignored mapping
table (see experiments/mitre_mapping/REPORT.md 8a.9). Without the table digest
on the page, a reader cannot tell the arms apart from the artifacts.

Rendered server-side as static SVG rather than drawn in JS: the page is a
comparison, not an explorer, so there is nothing to hover or filter, and a
static document is verifiable by reading it.

Usage:
    python -m evaluation.arm_dashboard ../eval-sensitivity \\
        --out ../eval-sensitivity/arms.html
"""

import argparse
import json
import os

# Same validated palette as evaluation/dashboard.py -- chrome and data share
# one colour system rather than two that nearly agree.
SERIES_LIGHT = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']
SERIES_DARK = ['#3987e5', '#d95926', '#199e70', '#c98500']

# Arm order is fixed rather than sorted, so the baseline reads first and the
# variants stay in the same colour slot on every dataset's chart.
ARM_ORDER = ['aif', 'kill-chain', 'impact-only', 'aif-aligned']

# (label, dotted path into the record's reference section, higher_is_better)
# `None` marks a metric that is neither good nor bad on its own: the objective
# count is a property of the taxonomy (AIF distinguishes 13 high-severity
# stages, the hybrid ATT&CK arms 4), and graph counts cannot be ranked without
# a coverage figure beside them.
METRICS = [
    ('Attack graphs', 'attack_graphs.aggregate.n_attack_graphs', None),
    ('Victims with a graph', 'attack_graphs.aggregate.n_victims', None),
    ('Objectives', 'attack_graphs.aggregate.n_objectives', None),
    ('Total nodes', 'attack_graphs.aggregate.total_nodes', None),
    ('Unique nodes', 'attack_graphs.aggregate.unique_nodes', None),
    ('Total edges', 'attack_graphs.aggregate.total_edges', None),
    ('Unique edges', 'attack_graphs.aggregate.unique_edges', None),
    ('Alerts per graph', 'compression.raw_alerts_per_ag', None),
    ('Alerts per node', 'compression.raw_alerts_per_ag_node', None),
    ('Perplexity (training)', 'perplexity.training.perplexity', False),
    ('Perplexity (held-out)', 'perplexity.heldout.perplexity', False),
    ('Wall clock (s)', 'timing.wall_clock_seconds', False),
    ('Alerts/sec', 'timing.alert_throughput', True),
]

# Drawn as bars. Deliberately only the two coverage metrics: they are the ones
# the severity table moves, and a chart of thirteen metrics at three scales
# communicates less than a table of the same numbers.
CHART_METRICS = [
    ('Attack graphs', 'attack_graphs.aggregate.n_attack_graphs'),
    ('Victims with a graph', 'attack_graphs.aggregate.n_victims'),
]

# arm -> (annotation, what counts as a HIGH-severity objective, what it is).
# Spelled out on the page because the arm names are internal shorthand and the
# page is read by people who did not choose them.
ARM_NOTES = {
    'aif': (
        'Action-Intent Framework — SAGE as published',
        'Exploitation onwards: 13 stages including DATA_EXFILTRATION and '
        'DATA_DELIVERY',
        'The baseline. Moskal &amp; Yang&rsquo;s taxonomy, which SAGE ships with. '
        'Its severity ordering is <em>published as part of the model</em>, '
        'which is what the ATT&amp;CK arms have no equivalent of.'),
    'kill-chain': (
        'ATT&amp;CK, literal reading',
        'Impact, Exfiltration, Command-and-Control',
        'Objectives are the end of the kill chain. Command-and-Control is '
        'included because the alerts driving AIF&rsquo;s exfiltration '
        'objectives map to C2 techniques (T1071 <em>Application Layer '
        'Protocol</em>, T1105 <em>Ingress Tool Transfer</em>) — demote it and '
        'those objectives disappear entirely.'),
    'impact-only': (
        'ATT&amp;CK, strictest reading',
        'Impact, Exfiltration',
        'Command-and-Control demoted to an enabler, on ATT&amp;CK&rsquo;s own '
        'description of it as <em>maintaining access</em> rather than '
        'achieving a goal. Differs from kill-chain by exactly one tactic.'),
    'aif-aligned': (
        'ATT&amp;CK with AIF&rsquo;s objective definition',
        'Impact, Exfiltration, Command-and-Control, <b>Initial Access</b>, '
        '<b>Lateral Movement</b>',
        'Exploitation terminates a graph, as it does in AIF. <b>Not '
        'ATT&amp;CK-faithful</b> — it was built to reproduce AIF&rsquo;s '
        'objective definition so the remaining difference is vocabulary, so it '
        'cannot also be independent evidence that AIF&rsquo;s definition is '
        'right.'),
}

# The vocabulary the rest of the page assumes. Listed because this document is
# read by people outside the project, and an unexplained abbreviation in a
# comparison is the same defect as an unexplained column.
TERMS = [
    ('Alert', 'One detection emitted by Suricata, the IDS. Every number on '
              'this page derives from a stream of these.'),
    ('Signature', 'The rule that fired an alert, named in prose &mdash; e.g. '
                  '<em>ET WEB_SERVER PHP tags in HTTP POST</em>. What the '
                  'label set maps to an ATT&amp;CK technique.'),
    ('Tactic', 'ATT&amp;CK&rsquo;s coarse layer: the attacker&rsquo;s goal at '
               'a step. Fourteen of them &mdash; Reconnaissance, Initial '
               'Access, Impact and so on.'),
    ('Technique', 'ATT&amp;CK&rsquo;s fine layer: how the goal was achieved, '
                  'identified as <code>T####</code> &mdash; e.g. '
                  '<code>T1190</code>, <em>Exploit Public-Facing '
                  'Application</em>. Each technique belongs to one or more '
                  'tactics.'),
    ('Command-and-Control (C2)', 'The tactic covering an attacker&rsquo;s '
                                 'channel back to a compromised host &mdash; '
                                 'beaconing to a server, pulling down tools. '
                                 'Whether that counts as an <em>objective</em> '
                                 'or merely an <em>enabler</em> is the single '
                                 'tactic separating the kill-chain and '
                                 'impact-only arms.'),
    ('Objective', 'A high-severity state. Reaching one terminates an attack '
                  'graph, which is why the tier assignment decides what gets '
                  'drawn.'),
    ('Victim', 'A destination host that alerts were raised against. SAGE '
               'builds attack graphs per victim.'),
    ('Attack graph', 'The pipeline&rsquo;s output: a directed graph of the '
                     'attacker actions leading to one objective against one '
                     'victim.'),
    ('Episode', 'A burst of alerts at the same attack stage, aggregated over '
                'a sliding window. The unit the model is learned from, not '
                'individual alerts.'),
    ('Trace', 'One attack attempt as a sequence of episode symbols, which is '
              'what gets fed to the model learner.'),
    ('S-PDFA', 'Suffix-based Probabilistic Deterministic Finite Automaton '
               '&mdash; the state machine SAGE learns from the traces and '
               'then walks to build the graphs.'),
    ('FlexFringe', 'The external tool that learns the S-PDFA. A Linux binary, '
                   'which is why the pipeline does not run natively on '
                   'Windows.'),
]

# metric label -> what it counts and how to read it.
METRIC_NOTES = {
    'Attack graphs': 'One graph per victim per high-severity objective reached. '
                     'Coverage multiplied by objective granularity, so it is '
                     'not comparable across taxonomies on its own.',
    'Victims with a graph': 'Distinct victim hosts with at least one attack '
                            'graph. The coverage measure, and the one that is '
                            'comparable across taxonomies.',
    'Objectives': 'Distinct high-severity stages that terminated a graph. A '
                  'property of the taxonomy&rsquo;s granularity, not a quality '
                  'score — AIF distinguishes more of them by construction.',
    'Total nodes': 'Nodes summed over every graph; a node is one attacker '
                   'action (stage plus service).',
    'Unique nodes': 'Distinct nodes across all graphs — the size of the '
                    'observed behaviour vocabulary.',
    'Total edges': 'Edges summed over every graph; an edge is one observed '
                   'transition between actions.',
    'Unique edges': 'Distinct transitions across all graphs.',
    'Alerts per graph': 'Raw alerts divided by graphs. Reads as compression, '
                        'but rises when coverage collapses — always read it '
                        'next to the victim count.',
    'Alerts per node': 'Raw alerts divided by total graph nodes. Same caveat.',
    'Perplexity (training)': 'How well the learned S-PDFA predicts the traces '
                             'it was trained on. Lower is better. Comparable '
                             'to the figure in the SAGE paper.',
    'Perplexity (held-out)': 'The same measure against traces held out before '
                             'learning, which needs a second FlexFringe run. '
                             'Lower is better; this is the one that says '
                             'whether the model generalises.',
    'Wall clock (s)': 'End-to-end pipeline runtime. Machine-dependent, and '
                      'sensitive to whatever else was running.',
    'Alerts/sec': 'Alert throughput. Same caveat as wall clock.',
}


def dig(record, dotted):
    """
    Reads a dotted path out of a record, returning None rather than raising.

    @param record: the record's `reference` section
    @param dotted: e.g. 'attack_graphs.aggregate.n_attack_graphs'
    @return: the numeric value, or None if absent or non-numeric
    """
    node = record
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    if isinstance(node, bool) or not isinstance(node, (int, float)):
        return None
    return node


def load(root, datasets=None):
    """
    Loads every arm's record and provenance stamp.

    @param root: directory holding one subdirectory per arm
    @param datasets: dataset keys to include, or None for all present
    @return: (ordered_arms, {dataset: {arm: reference}}, {arm: variant_record})
    """
    arms, found, provenance = [], {}, {}
    present = sorted(name for name in os.listdir(root)
                     if os.path.isdir(os.path.join(root, name))
                     and not name.startswith('_'))
    # Known arms first in their fixed order, then anything else alphabetically,
    # so an arm added later still renders instead of being silently dropped.
    for arm in [a for a in ARM_ORDER if a in present] + \
               [a for a in present if a not in ARM_ORDER]:
        stamp = os.path.join(root, arm, 'variant.json')
        if os.path.exists(stamp):
            with open(stamp, 'r', encoding='utf-8') as handle:
                provenance[arm] = json.load(handle)
        seen = False
        for name in sorted(os.listdir(os.path.join(root, arm))):
            if not (name.startswith('metrics-') and name.endswith('.json')):
                continue
            dataset = name[len('metrics-'):-len('.json')]
            if datasets and dataset not in datasets:
                continue
            with open(os.path.join(root, arm, name), 'r', encoding='utf-8') as handle:
                record = json.load(handle)
            found.setdefault(dataset, {})[arm] = {
                'reference': record.get('reference') or {},
                'commit': record.get('measured_commit'),
                'created_at': record.get('created_at'),
            }
            seen = True
        if seen:
            arms.append(arm)
    if not found:
        raise FileNotFoundError('No <arm>/metrics-*.json under {}'.format(root))
    return arms, found, provenance


def _fmt(value):
    """Formats a metric for display, keeping integers integral."""
    if value is None:
        return '--'
    if isinstance(value, float) and not value.is_integer():
        return '{:,.2f}'.format(value)
    return '{:,}'.format(int(value))


def _delta(value, base):
    """
    Percentage change against the baseline arm.

    @return: (text, sign) where sign is 'up', 'down' or '' -- sign drives only
        the arrow, never a good/bad colour, because most of these metrics have
        no better direction (see METRICS).
    """
    if value is None or base in (None, 0):
        return '', ''
    change = 100.0 * (value - base) / base
    if abs(change) < 0.05:
        return 'same', ''
    return '{:+.1f}%'.format(change), ('up' if change > 0 else 'down')


def _bars(dataset, arms, per_arm):
    """
    Renders the coverage bar chart for one dataset as inline SVG.

    Every bar is direct-labelled with its value: two of the four categorical
    slots sit below 3:1 contrast on the light surface, where a legend alone
    would not be readable.

    @param dataset: the dataset key, used for element ids
    @param arms: ordered arm names
    @param per_arm: {arm: reference}
    @return: an SVG string
    """
    width, row_height, gap, label_width = 640, 26, 10, 150
    groups = []
    for title, path in CHART_METRICS:
        values = [(arm, dig(per_arm[arm]['reference'], path)) for arm in arms]
        groups.append((title, [(a, v) for a, v in values if v is not None]))
    groups = [g for g in groups if g[1]]
    if not groups:
        return ''

    peak = max(v for _, values in groups for _, v in values) or 1
    height = sum(len(values) * row_height + 34 for _, values in groups) + 8
    out = ['<svg viewBox="0 0 {} {}" role="img" aria-label="Coverage by arm, '
           '{}" class="bars">'.format(width, height, dataset)]
    y = 18
    for title, values in groups:
        out.append('<text x="0" y="{}" class="bt">{}</text>'.format(y, title))
        y += 14
        for index, (arm, value) in enumerate(values):
            colour = 'var(--ink-2)' if arm == arms[0] else 'var(--s{})'.format(
                (ARM_ORDER.index(arm) if arm in ARM_ORDER else index) % 4)
            span = max(2.0, (width - label_width - 70) * value / peak)
            out.append('<text x="0" y="{}" class="bl">{}</text>'
                       .format(y + 12, arm))
            out.append('<rect x="{}" y="{}" width="{:.1f}" height="14" rx="3" '
                       'fill="{}"/>'.format(label_width, y + 2, span, colour))
            out.append('<text x="{:.1f}" y="{}" class="bv">{}</text>'
                       .format(label_width + span + 6, y + 13, _fmt(value)))
            y += row_height
        y += 20
    out.append('</svg>')
    return '\n'.join(out)


def _metric_table(arms, per_arm):
    """Renders the metric table for one dataset, with deltas against arms[0]."""
    baseline = arms[0]
    head = ''.join('<th>{}{}</th>'.format(
        arm, '' if arm != baseline else ' <span class="tag">baseline</span>')
        for arm in arms)
    rows = []
    for label, path, _ in METRICS:
        base = dig(per_arm[baseline]['reference'], path)
        if all(dig(per_arm[a]['reference'], path) is None for a in arms):
            continue                      # metric absent from every arm
        cells = []
        for arm in arms:
            value = dig(per_arm[arm]['reference'], path)
            text, sign = ('', '') if arm == baseline else _delta(value, base)
            cells.append('<td><span class="v">{}</span>{}</td>'.format(
                _fmt(value),
                '' if not text else
                '<span class="d {}">{}</span>'.format(sign, text)))
        rows.append('<tr><td class="name">{}</td>{}</tr>'.format(label, ''.join(cells)))
    return ('<table><thead><tr><th class="name">Metric</th>{}</tr></thead>'
            '<tbody>{}</tbody></table>'.format(head, ''.join(rows)))


def _arm_glossary(arms):
    """
    Renders what each arm actually is.

    The arm names are internal shorthand -- `aif-aligned` means nothing to a
    reader who has not read 8a.9 -- and a comparison whose columns are
    undefined cannot be checked by anyone but its author.
    """
    rows = []
    for arm in arms:
        heading, objectives, description = ARM_NOTES.get(
            arm, ('--', '--', 'No description recorded for this arm.'))
        rows.append('<tr><td class="name"><b>{}</b><br><span class="sub">{}</span>'
                    '</td><td class="wrap">{}</td><td class="wrap">{}</td></tr>'
                    .format(arm, heading, objectives, description))
    return ('<table><thead><tr><th class="name">Arm</th>'
            '<th class="wrap">Counts as a HIGH-severity objective</th>'
            '<th class="wrap">What it is</th></tr></thead><tbody>{}</tbody>'
            '</table>'.format(''.join(rows)))


def _terms():
    """Renders the vocabulary the page assumes, in reading order."""
    return ('<dl class="terms">{}</dl>'.format(''.join(
        '<dt>{}</dt><dd>{}</dd>'.format(term, definition)
        for term, definition in TERMS)))


def _metric_glossary():
    """Renders what each metric counts, in the table's own row order."""
    rows = []
    for label, _, better in METRICS:
        direction = {True: 'higher is better', False: 'lower is better',
                     None: 'neither better nor worse on its own'}[better]
        rows.append('<tr><td class="name">{}</td><td class="wrap">{}</td>'
                    '<td class="sub">{}</td></tr>'
                    .format(label, METRIC_NOTES.get(label, ''), direction))
    return ('<table><thead><tr><th class="name">Metric</th>'
            '<th class="wrap">What it counts</th><th>Direction</th></tr>'
            '</thead><tbody>{}</tbody></table>'.format(''.join(rows)))


def _provenance(arms, provenance):
    """Renders the table that says which severity table produced each arm."""
    rows = []
    for arm in arms:
        stamp = provenance.get(arm) or {}
        tiers = stamp.get('codes_by_severity') or {}
        rows.append(
            '<tr><td class="name">{}</td><td>{}</td><td>{}</td><td>{}</td>'
            '<td class="mono">{}</td></tr>'.format(
                arm,
                stamp.get('SAGE_TAXONOMY', '--'),
                stamp.get('SAGE_SEVERITY_VARIANT') or 'published (AIF)',
                '/'.join(str(tiers.get(k, '--')) for k in ('low', 'medium', 'high'))
                if tiers else '--',
                (stamp.get('table_sha256') or '--')[:12]))
    return ('<table><thead><tr><th class="name">Arm</th><th>SAGE_TAXONOMY</th>'
            '<th>Severity variant</th><th>Codes low/med/high</th>'
            '<th>Table sha256</th></tr></thead><tbody>{}</tbody></table>'
            .format(''.join(rows)))


def render(arms, found, provenance):
    """
    Renders the comparison document.

    @param arms: ordered arm names
    @param found: {dataset: {arm: record}}
    @param provenance: {arm: variant record}
    @return: the HTML document body
    """
    sections = []
    for dataset in sorted(found):
        per_arm = found[dataset]
        present = [a for a in arms if a in per_arm]
        missing = [a for a in arms if a not in per_arm]
        note = ('' if not missing else
                '<p class="missing">Not run on this dataset: {}.</p>'
                .format(', '.join(missing)))
        sections.append(
            '<section class="card"><h2>{}</h2>{}<div class="tablewrap">{}</div>'
            '<div class="chart">{}</div></section>'
            .format(dataset, note,
                    _metric_table(present, per_arm),
                    _bars(dataset, present, per_arm)))

    commits = sorted({record['commit'][:7] for per_arm in found.values()
                      for record in per_arm.values() if record.get('commit')})
    return _TEMPLATE \
        .replace('__SECTIONS__', ''.join(sections)) \
        .replace('__ARMS__', _arm_glossary(arms)) \
        .replace('__GLOSSARY__', _metric_glossary()) \
        .replace('__TERMS__', _terms()) \
        .replace('__PROVENANCE__', _provenance(arms, provenance)) \
        .replace('__COMMITS__', ', '.join(commits) or 'unknown') \
        .replace('__DATASETS__', ', '.join(sorted(found))) \
        .replace('__SERIES_LIGHT__', ''.join(
            '  --s{}: {};\n'.format(i, c) for i, c in enumerate(SERIES_LIGHT))) \
        .replace('__SERIES_DARK__', ''.join(
            '  --s{}: {};\n'.format(i, c) for i, c in enumerate(SERIES_DARK)))


def write(root, output_path, datasets=None):
    """
    Loads the arms and writes the comparison page.

    @param root: directory holding one subdirectory per arm
    @param output_path: the .html file to write
    @param datasets: dataset keys, or None for all present
    @return: the output path
    """
    arms, found, provenance = load(root, datasets)
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as handle:
        handle.write(render(arms, found, provenance))
    return output_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', help='directory holding one subdir per arm')
    parser.add_argument('--out', default=None,
                        help='output HTML (default: <root>/arms.html)')
    parser.add_argument('--datasets', nargs='*', default=None)
    args = parser.parse_args()
    path = write(args.root, args.out or os.path.join(args.root, 'arms.html'),
                 args.datasets)
    print('Wrote {}'.format(path))


_TEMPLATE = r"""<title>Severity Arm Comparison</title>
<style>
:root {
  --surface: #fcfcfb;
  --raised:  #ffffff;
  --ink:     #0b0b0b;
  --ink-2:   #52514e;
  --ring:    rgba(11,11,11,0.12);
  --accent:  #2a78d6;
__SERIES_LIGHT__}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --surface: #1a1a19;
    --raised:  #232320;
    --ink:     #ffffff;
    --ink-2:   #c3c2b7;
    --ring:    rgba(255,255,255,0.16);
    --accent:  #3987e5;
__SERIES_DARK__  }
}
:root[data-theme="dark"] {
  --surface: #1a1a19;
  --raised:  #232320;
  --ink:     #ffffff;
  --ink-2:   #c3c2b7;
  --ring:    rgba(255,255,255,0.16);
  --accent:  #3987e5;
__SERIES_DARK__}
body {
  background: var(--surface); color: var(--ink); margin: 0;
  font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  padding: 28px 16px 56px;
}
.wrap { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 21px; margin: 0 0 6px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 0 0 12px; }
p  { margin: 0 0 12px; color: var(--ink-2); }
.meta { font-size: 12.5px; color: var(--ink-2); margin-bottom: 20px; }
.meta b { font-weight: 600; color: var(--ink); }
.card {
  background: var(--raised); border: 1px solid var(--ring); border-radius: 12px;
  padding: 18px 18px 14px; margin: 0 0 18px;
}
.lede {
  background: var(--raised); border: 1px solid var(--ring); border-left: 3px solid var(--accent);
  border-radius: 10px; padding: 14px 16px; margin: 0 0 20px; font-size: 13.5px;
}
.lede p:last-child { margin-bottom: 0; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td {
  text-align: right; padding: 7px 10px; border-bottom: 1px solid var(--ring);
  white-space: nowrap;
}
th { color: var(--ink-2); font-weight: 600; font-size: 12px; }
th.name, td.name { text-align: left; color: var(--ink); }
td { color: var(--ink-2); font-variant-numeric: tabular-nums; }
td .v { color: var(--ink); }
td .d { display: inline-block; margin-left: 8px; font-size: 11.5px; opacity: 0.85; }
td .d.up::before  { content: "\2191 "; }
td .d.down::before { content: "\2193 "; }
.tag {
  font-size: 10.5px; font-weight: 500; color: var(--ink-2); border: 1px solid var(--ring);
  border-radius: 999px; padding: 1px 6px; margin-left: 4px;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
th.wrap, td.wrap { white-space: normal; text-align: left; min-width: 180px; }
td.sub, .sub { color: var(--ink-2); font-size: 11.5px; font-weight: 400; white-space: normal; }
dl.terms { margin: 0; display: grid; grid-template-columns: minmax(130px, 210px) 1fr; gap: 6px 18px; font-size: 13px; }
dl.terms dt { color: var(--ink); font-weight: 600; }
dl.terms dd { margin: 0; color: var(--ink-2); }
dl.terms code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: var(--ink); }
@media (max-width: 560px) { dl.terms { grid-template-columns: 1fr; gap: 2px; } dl.terms dd { margin-bottom: 10px; } }
.missing { font-size: 12.5px; }
.chart { margin-top: 16px; }
svg.bars { width: 100%; height: auto; overflow: visible; }
svg.bars .bt { fill: var(--ink); font-size: 12px; font-weight: 600; }
svg.bars .bl { fill: var(--ink-2); font-size: 11.5px; }
svg.bars .bv { fill: var(--ink); font-size: 11.5px; font-variant-numeric: tabular-nums; }
@media (max-width: 560px) { body { padding: 20px 12px 40px; } }
</style>
<div class="wrap">
<h1>Severity arm comparison</h1>
<div class="meta">
  Datasets: <b>__DATASETS__</b> &middot; commits: <b>__COMMITS__</b>
</div>

<div class="lede">
<p><b>What varies between these arms is the severity tier table, not the
taxonomy.</b> SAGE renders one attack graph per victim per high-severity
objective, so which tactics count as HIGH decides what can terminate a graph.
AIF publishes that ordering; MITRE ATT&amp;CK does not, so the ATT&amp;CK arms
use a tier table written for this project.</p>
<p>The three ATT&amp;CK arms hold the label set, vocabulary, level, unmapped
policy, IANA snapshot and seed constant and differ only in that table. Deltas
are against the <code>aif</code> arm. A spread across three hand-chosen
configurations is not an error bar &mdash; and <code>aif-aligned</code> was
built to reproduce AIF&rsquo;s objective definition, so it cannot also be
independent evidence that AIF&rsquo;s definition is right.</p>
</div>

<section class="card">
<h2>Terms</h2>
__TERMS__
</section>

<section class="card">
<h2>The arms</h2>
<p>SAGE grades every alert into three severity tiers &mdash; low (scanning),
medium (enablers: getting in, moving, persisting) and high (the attacker&rsquo;s
objective). Only a <b>high</b>-severity state can terminate an attack graph, so
which tactics sit in that tier decides what the pipeline will draw. All three
ATT&amp;CK arms share one vocabulary and one label set; they differ only in
where that line is drawn.</p>
<div class="tablewrap">__ARMS__</div>
</section>

__SECTIONS__

<section class="card">
<h2>What the metrics mean</h2>
<div class="tablewrap">__GLOSSARY__</div>
</section>

<section class="card">
<h2>Provenance</h2>
<p>Each arm&rsquo;s severity table is generated and gitignored, so arms measured
together record the same commit. The digest below is what actually
distinguishes them; it comes from each arm&rsquo;s <code>variant.json</code>.
Tier counts are of the symbol table the pipeline loaded, so <code>low</code>
includes the <code>unmapped</code> catch-all code.</p>
<p>More than one commit in the header means the datasets were measured at
different times. That is only comparable if no pipeline code changed between
them &mdash; check with <code>git diff --stat &lt;a&gt; &lt;b&gt;</code> before
reading across datasets.</p>
<div class="tablewrap">__PROVENANCE__</div>
</section>
</div>
"""


if __name__ == '__main__':
    main()
