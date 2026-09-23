"""
Renders how well each attempt at signature-to-ATT&CK mapping actually worked.

There is no single accuracy number for this work, and a dashboard that implied
there was would be worse than none. The attempts span five evaluation regimes
with different eval sets, denominators and scoring rules, so the page is built
around keeping them apart: one panel per regime, no global leaderboard, and no
sort that would let a regime-E number sit above a regime-D one.

Three sources, three different levels of trust, each labelled as such:

  * **Regimes A-E** come from `mapping_results.json`, a transcription of
    REPORT.md section 11. Those runs are no longer reproducible -- the eval
    sets and scoring rules changed under them -- so they are recorded rather
    than measured. `check_mapping_results.py` verifies the transcription.
  * **Entity-normalisation arms** are parsed live from the
    `validation_report_*.md` files each arm wrote, so they cannot drift from
    the artifacts.
  * **The oracle condition** is separated out entirely. It assumes a working
    mapper rather than measuring one, so it is an upper bound and belongs
    nowhere near the generalisation numbers.

Usage:
    python experiments/mitre_mapping/mapping_dashboard.py \\
        --out experiments/mitre_mapping/mapping.html
"""

import argparse
import glob
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

SERIES_LIGHT = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']
SERIES_DARK = ['#3987e5', '#d95926', '#199e70', '#c98500']

# The arm whose retrieval pool contains the oracle corpus is not a
# generalisation measurement, whatever its filename says.
ORACLE_MARKER = 'alert_oracle_corpus'

# Effort 19 added the alert corpus and moved the regime-D baseline from
# 36.6/22.2 to 40.2/28.7. Arms run either side of it are therefore NOT
# comparable to each other, even though every one of them is regime D on the
# same 361 rows -- the entity change is measured against whichever corpus was
# loaded. The retrieval-pool line names the corpora, so the era is detectable
# rather than guessed: 'alert' present means the later baseline.
ALERT_CORPUS_KEY = "'alert'"
BASELINES = {
    'with-alert': {'micro': 40.2, 'macro': 28.7, 'label': 'effort 19 corpus',
                   'note': 'the alert corpus is loaded, so these compare to '
                           '40.2% / 28.7%'},
    'pre-alert': {'micro': 36.6, 'macro': 22.2, 'label': 'pre-effort-19 corpus',
                  'note': 'measured before the alert corpus existed, so these '
                          'compare to 36.6% / 22.2%'},
}

PERCENT = re.compile(r'([0-9]+\.[0-9]+)%')

# Defined per-SVG rather than once in the page: each diagram is self-contained,
# so a marker defined in a sibling would break if either were reused alone.
_ARROWHEAD = ('<defs><marker id="ah" viewBox="0 0 8 8" refX="7" refY="4" '
              'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
              '<path d="M0,0 L8,4 L0,8 z" fill="currentColor" '
              'class="link"/></marker></defs>')


def _pct(line):
    """First percentage on a line, or None."""
    found = PERCENT.search(line or '')
    return float(found.group(1)) if found else None


def read_validation_reports(directory):
    """
    Parses the headline of every validation_report_*.md in `directory`.

    @param directory: where the reports live
    @return: (arms, oracle) -- lists of dicts; `oracle` holds any report whose
        retrieval pool includes the oracle corpus, kept apart deliberately
    """
    arms, oracle = [], []
    for path in sorted(glob.glob(os.path.join(directory, 'validation_report*.md'))):
        with open(path, 'r', encoding='utf-8') as handle:
            text = handle.read()
        record = {'name': os.path.basename(path), 'micro': None, 'macro': None,
                  'scoreable': None, 'oracle': ORACLE_MARKER in text,
                  'era': 'pre-alert'}
        for line in text.splitlines():
            if 'kNN retrieval pool' in line and ALERT_CORPUS_KEY in line:
                record['era'] = 'with-alert'
            if line.startswith('- top-1 correct') and record['micro'] is None:
                record['micro'] = _pct(line)
            elif '**macro-average**' in line and record['macro'] is None:
                record['macro'] = _pct(line)
            elif line.startswith('- scoreable') and record['scoreable'] is None:
                found = re.search(r'\*\*(\d+)\*\*', line)
                record['scoreable'] = int(found.group(1)) if found else None
        # A report with no headline is a stub or a failed run; showing it as a
        # blank row invites the reader to treat absence as zero.
        if record['micro'] is None:
            continue
        record['label'] = (record['name']
                           .replace('validation_report_entity_', '')
                           .replace('validation_report_', '')
                           .replace('.md', '')) or 'baseline'
        (oracle if record['oracle'] else arms).append(record)
    return arms, oracle


def _fmt(value, suffix='%'):
    return '--' if value is None else '{:.1f}{}'.format(value, suffix)


def _regime_table(regime):
    """One regime's results table, columns exactly as recorded."""
    head = ''.join('<th{}>{}</th>'.format(
        ' class="name"' if i < 2 else '', column)
        for i, column in enumerate(regime['columns']))
    body = []
    for row in regime['rows']:
        cells = []
        for i, value in enumerate(row):
            if i < 2:
                cells.append('<td class="name">{}</td>'.format(value))
            elif isinstance(value, (int, float)):
                cells.append('<td>{}</td>'.format(_fmt(value)))
            else:
                cells.append('<td class="sub">{}</td>'.format(
                    value if value is not None else '--'))
        body.append('<tr>{}</tr>'.format(''.join(cells)))
    return ('<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>'
            .format(head, ''.join(body)))


def _bars(rows, value_index, label_index, peak=100.0):
    """
    A horizontal bar per row, direct-labelled.

    Scaled to 100 rather than to the maximum in the panel: these are
    percentages of a fixed ceiling, and rescaling each panel to its own best
    result would make a 6% row look competitive.
    """
    width, row_height, label_width = 620, 22, 250
    drawable = [r for r in rows if isinstance(r[value_index], (int, float))]
    if not drawable:
        return ''
    out = ['<svg viewBox="0 0 {} {}" class="bars" role="img" '
           'aria-label="accuracy by configuration">'
           .format(width, len(drawable) * row_height + 8)]
    y = 4
    for row in drawable:
        value = row[value_index]
        span = max(1.5, (width - label_width - 60) * value / peak)
        text = str(row[label_index])
        out.append('<text x="0" y="{}" class="bl">{}</text>'
                   .format(y + 12, text[:44] + ('…' if len(text) > 44 else '')))
        out.append('<rect x="{}" y="{}" width="{:.1f}" height="12" rx="3" '
                   'fill="var(--s0)"/>'.format(label_width, y + 2, span))
        out.append('<text x="{:.1f}" y="{}" class="bv">{}</text>'
                   .format(label_width + span + 6, y + 12, _fmt(value)))
        y += row_height
    out.append('</svg>')
    return '\n'.join(out)


def _box(x, y, w, h, title, detail, state='on', badge=None):
    """One labelled node. `state` 'off' renders dashed and muted."""
    cls = 'node off' if state == 'off' else 'node'
    out = ['<rect x="{}" y="{}" width="{}" height="{}" rx="6" class="{}"/>'
           .format(x, y, w, h, cls),
           '<text x="{}" y="{}" class="nt">{}</text>'.format(x + 10, y + 18, title)]
    for i, line in enumerate(detail):
        out.append('<text x="{}" y="{}" class="nd">{}</text>'
                   .format(x + 10, y + 33 + i * 12, line))
    if badge:
        out.append('<text x="{}" y="{}" class="nb">{}</text>'
                   .format(x + w - 10, y + 18, badge))
    return out


def _arrow(x1, y1, x2, y2, dashed=False, label=None):
    """A straight connector with an arrowhead, optionally labelled."""
    cls = 'link dashed' if dashed else 'link'
    out = ['<line x1="{}" y1="{}" x2="{}" y2="{}" class="{}" '
           'marker-end="url(#ah)"/>'.format(x1, y1, x2, y2, cls)]
    if label:
        out.append('<text x="{}" y="{}" class="ll">{}</text>'
                   .format((x1 + x2) / 2.0, (y1 + y2) / 2.0 - 4, label))
    return out


def _cascade_svg(pipeline):
    """
    The resolver cascade, in priority order, carrying its own accuracy.

    Drawn rather than listed because the ordering *is* the mechanism: each
    resolver only sees rows the ones above it did not claim, so a high-accuracy
    source low in the chain is not the same as a high-accuracy pipeline. Pairing
    each box with its measured accuracy and volume is what makes the
    under-harvested top of the chain visible.
    """
    width, box_h, gap, box_w, left = 660, 62, 16, 430, 26
    steps = pipeline['cascade']
    height = len(steps) * (box_h + gap) + 8
    out = ['<svg viewBox="0 0 {} {}" class="diagram" role="img" '
           'aria-label="resolver cascade in priority order">{}'
           .format(width, height, _ARROWHEAD)]
    y = 4
    for index, step in enumerate(steps):
        detail = [step['detail']]
        if step.get('note'):
            detail.append(step['note'])
        badge = None
        if step.get('accuracy') is not None:
            # "of N claimed" rather than "(N rows)": the page uses "row" for a
            # corpus row elsewhere, and the two counts are unrelated.
            badge = '{:.1f}%'.format(step['accuracy'])
            if step.get('rows'):
                badge += ' of {} claimed'.format(step['rows'])
        elif step.get('state') == 'off':
            badge = 'off'
        # Provenance on the box, because these accuracies are not one run and
        # the page's own rule forbids comparing across regimes. Without it the
        # diagram reads as a single measurement, which it is not.
        if step.get('effort'):
            detail.append('measured: effort {} · regime {}'
                          .format(step['effort'], step['regime']))
        out.append('<text x="0" y="{}" class="nn">{}</text>'.format(y + 20, index + 1))
        out += _box(left, y, box_w, box_h, step['id'], detail,
                    step.get('state', 'on'), badge)
        if index < len(steps) - 1:
            out += _arrow(left + box_w / 2, y + box_h, left + box_w / 2,
                          y + box_h + gap - 2,
                          dashed=steps[index + 1].get('state') == 'off')
        y += box_h + gap
    out.append('</svg>')
    return '\n'.join(out)


def _sources_svg(pipeline):
    """
    Where each resolver's knowledge comes from.

    Nothing in the pipeline is hand-written per signature; every source derives
    from one of a handful of external artifacts. Drawing it shows the two
    couplings that explain most of the report: one corpus feeding two
    resolvers, and one gitignored rules file feeding two more.
    """
    sources = pipeline['sources']
    width = 760
    box_h, gap, col_w = 46, 12, 200
    height = max(len(sources) * (box_h + gap) + 10, 300)
    left_x, mid_x, right_x = 0, 270, 545

    out = ['<svg viewBox="0 0 {} {}" class="diagram" role="img" '
           'aria-label="knowledge sources feeding each resolver">{}'
           .format(width, height, _ARROWHEAD)]

    corpus_y = []
    y = 5
    positions = {}
    for source in sources:
        positions[source['id']] = y + box_h / 2
        out += _box(left_x, y, col_w, box_h, source['id'], [source['detail']],
                    source.get('state', 'on'))
        if source['target'] == 'corpus':
            corpus_y.append(y + box_h / 2)
        y += box_h + gap

    # Middle column: the single chokepoint both the classifier and kNN share.
    mid_y = sum(corpus_y) / len(corpus_y) - box_h
    out += _box(mid_x, mid_y - 30, col_w, box_h, 'corpora.py',
                ['32,048 labelled rows in use'])
    out += _box(mid_x, mid_y + 34, col_w, box_h, 'normalize.canonicalize',
                ['corpus and query take the same path'])
    out += _arrow(mid_x + col_w / 2, mid_y - 30 + box_h, mid_x + col_w / 2, mid_y + 32)

    for source in sources:
        if source['target'] == 'corpus':
            out += _arrow(left_x + col_w + 4, positions[source['id']],
                          mid_x - 4, mid_y - 30 + box_h / 2,
                          dashed=source.get('state') == 'off')

    # Right column: the consumers.
    consumers = [('supervised_classifier', 'trains on these rows', mid_y + 10),
                 ('knn_corpus', 'retrieves against these rows', mid_y + 70)]
    for name, detail, cy in consumers:
        out += _box(right_x, cy, col_w, box_h, name, [detail])
        out += _arrow(mid_x + col_w + 4, mid_y + 34 + box_h / 2,
                      right_x - 4, cy + box_h / 2)

    stix = positions.get('MITRE STIX bundle')
    rules = positions.get('emerging-all.rules')
    if stix is not None:
        out += _box(right_x, stix - box_h / 2, col_w, box_h, 'ioc_alias',
                    ['alias table + stoplist'])
        out += _arrow(left_x + col_w + 4, stix, right_x - 4, stix)
    if rules is not None:
        out += _box(right_x, rules - box_h / 2, col_w, box_h,
                    'declared + extractor', ['reads the vendor tag'])
        out += _arrow(left_x + col_w + 4, rules, right_x - 4, rules)

    out.append('</svg>')
    return '\n'.join(out)


# The panel's baselines are regime D figures, so only arms scored on regime D's
# denominator may carry a delta against them. Detected from the report's own
# scoreable count rather than from filenames, because a filename does not say
# which eval set produced it -- `validation_report_llm.md` is regime A (80
# scoreable) and was briefly rendered here as +25.9 against a regime-D
# baseline, which is meaningless.
REGIME_D_SCOREABLE = 361


def _arms_table(arms):
    """
    The entity-normalisation arms, grouped by the baseline they ran against.

    Every arm here is regime D on the same 361 rows, which makes them look
    mutually comparable -- and they are not. Effort 19 added the alert corpus
    and moved the baseline from 36.6/22.2 to 40.2/28.7, so an arm measured
    before that is scored against a different reference than one measured
    after. Ranking them in one list would repeat, one panel down, exactly the
    cross-regime comparison this page opens by forbidding.
    """
    on_frame = [a for a in arms if a.get('scoreable') == REGIME_D_SCOREABLE]
    off_frame = [a for a in arms if a.get('scoreable') != REGIME_D_SCOREABLE]

    blocks = []
    for era in ('with-alert', 'pre-alert'):
        group = [a for a in on_frame if a.get('era') == era]
        if not group:
            continue
        base = BASELINES[era]
        group.sort(key=lambda a: -(a['micro'] or 0))
        body = []
        for arm in group:
            cells = []
            for field in ('micro', 'macro'):
                value = arm[field]
                delta = ('' if value is None else
                         '<span class="d">{:+.1f}</span>'
                         .format(value - base[field]))
                cells.append('<td><span class="v">{}</span>{}</td>'
                             .format(_fmt(value), delta))
            body.append('<tr><td class="name">{}</td>{}'
                        '<td class="sub mono">{}</td></tr>'
                        .format(arm['label'], ''.join(cells), arm['name']))
        blocks.append(
            '<h3>Against the {} baseline &mdash; {:.1f}% / {:.1f}%</h3>'
            '<p class="sub">{}. Deltas are against that baseline, not against '
            'the other group.</p>'
            '<div class="tablewrap"><table><thead><tr>'
            '<th class="name">Arm</th><th>micro</th><th>macro</th>'
            '<th class="sub">source file</th></tr></thead><tbody>{}</tbody>'
            '</table></div>'.format(base['label'], base['micro'],
                                    base['macro'], base['note'],
                                    ''.join(body)))

    if off_frame:
        rows = ''.join(
            '<tr><td class="name">{}</td><td>{}</td><td>{}</td>'
            '<td>{}</td><td class="sub mono">{}</td></tr>'.format(
                arm['label'], _fmt(arm['micro']), _fmt(arm['macro']),
                arm.get('scoreable') or '--', arm['name'])
            for arm in sorted(off_frame, key=lambda a: -(a['micro'] or 0)))
        blocks.append(
            '<h3>Measured on a different eval set &mdash; no delta shown</h3>'
            '<p class="caveat">These reports are not scored on regime D&rsquo;s '
            '361 rows, so neither baseline above applies to them and a delta '
            'would be meaningless. The LLM arm in particular is a regime A '
            'number, and its 62.5% is the <code>qwen2.5:7b</code> modal-collapse '
            'artifact recorded in that panel &mdash; not a result.</p>'
            '<div class="tablewrap"><table><thead><tr><th class="name">Arm</th>'
            '<th>micro</th><th>macro</th><th>scoreable</th>'
            '<th class="sub">source file</th></tr></thead><tbody>{}</tbody>'
            '</table></div>'.format(rows))
    return ''.join(blocks)


def render(results, arms, oracle):
    """Builds the document."""
    panels = []
    for regime in results['regimes']:
        flags = []
        if regime.get('current'):
            flags.append('<span class="tag current">current frame</span>')
        caveat = ('' if not regime.get('caveat') else
                  '<p class="caveat"><b>Caveat.</b> {}</p>'.format(regime['caveat']))
        buckets = ''
        if regime.get('buckets'):
            b = regime['buckets']
            rows = ''.join('<tr><td class="name">{}</td>{}</tr>'.format(
                row[0], ''.join('<td>{}</td>'.format(_fmt(v)) for v in row[1:]))
                for row in b['rows'])
            buckets = ('<h3>By class frequency</h3><p class="sub">{}</p>'
                       '<div class="tablewrap"><table><thead><tr>{}</tr></thead>'
                       '<tbody>{}</tbody></table></div>'.format(
                           b['note'],
                           ''.join('<th{}>{}</th>'.format(
                               ' class="name"' if i == 0 else '', c)
                               for i, c in enumerate(b['columns'])),
                           rows))
        # Value column is the first numeric one; label column is the config.
        value_index = 2
        panels.append(
            '<section class="card"><h2>Regime {} &mdash; {} {}</h2>'
            '<p class="sub"><b>{}</b>. {}</p>{}'
            '<div class="tablewrap">{}</div><div class="chart">{}</div>{}'
            '</section>'.format(
                regime['id'], regime['title'], ''.join(flags),
                regime['denominator'], regime.get('note', ''), caveat,
                _regime_table(regime), _bars(regime['rows'], value_index, 1),
                buckets))

    oracle_block = ''
    if oracle:
        rows = ''.join(
            '<tr><td class="name">{}</td><td>{}</td><td>{}</td>'
            '<td class="sub mono">{}</td></tr>'.format(
                o['label'], _fmt(o['micro']), _fmt(o['macro']), o['name'])
            for o in oracle)
        oracle_block = (
            '<section class="card oracle"><h2>Oracle condition &mdash; not a '
            'generalisation result</h2>'
            '<p>This run’s retrieval pool contains the oracle corpus, so it '
            'measures the pipeline <em>given</em> a working mapper rather than '
            'measuring whether the mapper works. It is an upper bound and a '
            'downstream-study input. <b>It does not belong in the same '
            'ranking as anything above.</b></p>'
            '<div class="tablewrap"><table><thead><tr><th class="name">Run</th>'
            '<th>micro</th><th>macro</th><th class="sub">source file</th></tr>'
            '</thead><tbody>{}</tbody></table></div></section>'.format(rows))

    pipeline = results.get('pipeline') or {}
    removed = ''.join(
        '<li><code>{}</code> &mdash; {:.1f}% (effort {} &middot; regime {}), '
        '{}</li>'.format(r['id'], r['accuracy'], r.get('effort', '?'),
                         r.get('regime', '?'), r['note'])
        for r in pipeline.get('removed', []))
    consequences = ''.join('<li>{}</li>'.format(c)
                           for c in pipeline.get('consequences', []))
    glossary = ''.join('<dt>{}</dt><dd>{}</dd>'.format(term, definition)
                       for term, definition in (pipeline.get('glossary')
                                                or {}).items())

    human = results.get('human_reference') or {}
    return _TEMPLATE \
        .replace('__CASCADE__', _cascade_svg(pipeline) if pipeline else '') \
        .replace('__SOURCES__', _sources_svg(pipeline) if pipeline else '') \
        .replace('__REMOVED__', removed) \
        .replace('__CONSEQUENCES__', consequences) \
        .replace('__PIPELINE_GLOSSARY__', glossary) \
        .replace('__PROV_WARNING__', pipeline.get('provenance_warning', '')) \
        .replace('__RULE__', results['rule']) \
        .replace('__HUMAN__', '{:.0f}%'.format(human.get('value', 0))) \
        .replace('__HUMAN_NOTE__', human.get('note', '')) \
        .replace('__PANELS__', ''.join(panels)) \
        .replace('__ARMS__', _arms_table(arms)) \
        .replace('__ORACLE__', oracle_block) \
        .replace('__SERIES_LIGHT__', ''.join(
            '  --s{}: {};\n'.format(i, c) for i, c in enumerate(SERIES_LIGHT))) \
        .replace('__SERIES_DARK__', ''.join(
            '  --s{}: {};\n'.format(i, c) for i, c in enumerate(SERIES_DARK)))


def write(output_path, directory=HERE):
    with open(os.path.join(directory, 'mapping_results.json'),
              'r', encoding='utf-8') as handle:
        results = json.load(handle)
    arms, oracle = read_validation_reports(directory)
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as handle:
        handle.write(render(results, arms, oracle))
    return output_path, len(arms), len(oracle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default=os.path.join(HERE, 'mapping.html'))
    args = parser.parse_args()
    path, n_arms, n_oracle = write(args.out)
    print('Wrote {} ({} arms parsed, {} oracle run(s) separated)'
          .format(path, n_arms, n_oracle))


_TEMPLATE = r"""<title>Signature to ATT&CK Mapping</title>
<style>
:root {
  --surface: #fcfcfb;
  --raised:  #ffffff;
  --ink:     #0b0b0b;
  --ink-2:   #52514e;
  --ring:    rgba(11,11,11,0.12);
  --accent:  #2a78d6;
  --warn:    #8a5a00;
  --warn-bg: rgba(237,161,0,0.12);
__SERIES_LIGHT__}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --surface: #1a1a19;
    --raised:  #232320;
    --ink:     #ffffff;
    --ink-2:   #c3c2b7;
    --ring:    rgba(255,255,255,0.16);
    --accent:  #3987e5;
    --warn:    #eda100;
    --warn-bg: rgba(237,161,0,0.16);
__SERIES_DARK__  }
}
:root[data-theme="dark"] {
  --surface: #1a1a19;
  --raised:  #232320;
  --ink:     #ffffff;
  --ink-2:   #c3c2b7;
  --ring:    rgba(255,255,255,0.16);
  --accent:  #3987e5;
  --warn:    #eda100;
  --warn-bg: rgba(237,161,0,0.16);
__SERIES_DARK__}
body {
  background: var(--surface); color: var(--ink); margin: 0;
  font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  padding: 28px 16px 56px;
}
.wrap { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 21px; margin: 0 0 6px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 0 0 10px; }
h3 { font-size: 13px; margin: 18px 0 6px; color: var(--ink-2); }
p  { margin: 0 0 12px; color: var(--ink-2); }
.card {
  background: var(--raised); border: 1px solid var(--ring); border-radius: 12px;
  padding: 18px; margin: 0 0 18px;
}
.lede {
  background: var(--raised); border: 1px solid var(--ring);
  border-left: 3px solid var(--accent); border-radius: 10px;
  padding: 14px 16px; margin: 0 0 20px; font-size: 13.5px;
}
.lede p:last-child { margin-bottom: 0; }
.rule {
  background: var(--warn-bg); border: 1px solid var(--ring);
  border-left: 3px solid var(--warn); border-radius: 10px;
  padding: 12px 16px; margin: 0 0 20px; font-size: 13.5px; color: var(--ink);
}
.caveat { font-size: 12.5px; background: var(--warn-bg); border-radius: 8px; padding: 9px 12px; }
.oracle { border-left: 3px solid var(--warn); }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: right; padding: 6px 10px; border-bottom: 1px solid var(--ring); white-space: nowrap; }
th { color: var(--ink-2); font-weight: 600; font-size: 12px; }
th.name, td.name { text-align: left; color: var(--ink); white-space: normal; }
td { color: var(--ink-2); font-variant-numeric: tabular-nums; }
td.sub, .sub { color: var(--ink-2); font-size: 12px; white-space: normal; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; }
.tag { font-size: 10.5px; border: 1px solid var(--ring); border-radius: 999px; padding: 1px 7px; color: var(--ink-2); font-weight: 500; }
.tag.current { border-color: var(--accent); color: var(--accent); }
.chart { margin-top: 14px; }
svg.bars { width: 100%; height: auto; overflow: visible; }
svg.bars .bl { fill: var(--ink-2); font-size: 11px; }
svg.bars .bv { fill: var(--ink); font-size: 11px; font-variant-numeric: tabular-nums; }
svg.diagram { width: 100%; height: auto; overflow: visible; }
svg.diagram .node { fill: var(--raised); stroke: var(--ring); stroke-width: 1.2; }
svg.diagram .node.off { stroke-dasharray: 4 3; opacity: 0.55; }
svg.diagram .nt { fill: var(--ink); font-size: 12.5px; font-weight: 600; }
svg.diagram .nd { fill: var(--ink-2); font-size: 10.5px; }
svg.diagram .nb { fill: var(--accent); font-size: 11px; text-anchor: end; font-variant-numeric: tabular-nums; }
svg.diagram .nn { fill: var(--ink-2); font-size: 11px; font-variant-numeric: tabular-nums; }
svg.diagram .link { stroke: var(--ink-2); stroke-width: 1.2; opacity: 0.6; }
svg.diagram .link.dashed { stroke-dasharray: 4 3; opacity: 0.4; }
svg.diagram .ll { fill: var(--ink-2); font-size: 10px; text-anchor: middle; }
ul.sub { margin: 0 0 4px; padding-left: 18px; }
ul.sub li { margin-bottom: 4px; }
dl.terms { margin: 0 0 16px; display: grid; grid-template-columns: minmax(90px, 130px) 1fr; gap: 5px 16px; font-size: 12.5px; }
dl.terms dt { color: var(--ink); font-weight: 600; }
dl.terms dd { margin: 0; color: var(--ink-2); }
@media (max-width: 560px) { dl.terms { grid-template-columns: 1fr; gap: 2px; } dl.terms dd { margin-bottom: 8px; } }
@media (max-width: 560px) { body { padding: 20px 12px 40px; } }
</style>
<div class="wrap">
<h1>Signature &rarr; ATT&amp;CK mapping: every attempt</h1>

<div class="lede">
<p>The task: given an IDS rule name in prose, predict the ATT&amp;CK technique
it represents &mdash; the step that would let SAGE drop its hand-coded lookup
table. Every attempt on this page is an attack on that one problem.</p>
<p>The reference point for all of it: a careful human reader agrees with
vendor-declared tags about <b>__HUMAN__</b> of the time. __HUMAN_NOTE__</p>
</div>

<section class="card">
<h2>How the mapper works</h2>
<p><code>attack_mapper/reasoner.py</code> takes one IDS rule and decides which
ATT&amp;CK technique it means. It does not run five predictors and vote: each
stage is guarded by <code>if not candidates</code>, so the chain is strictly
<b>first-match-wins</b> &mdash; if <code>declared</code> finds a vendor tag,
nothing below it runs for that signature at all. Confidence sorting happens
only <em>within</em> whichever single source fired.</p>
<p>That is why the order is the mechanism rather than a formality, and why a
high-accuracy source low in the chain is not the same thing as a high-accuracy
pipeline: each resolver is judged only on the leftovers of the ones above it,
which get harder the further down you go.</p>
<dl class="terms">__PIPELINE_GLOSSARY__</dl>
<p class="caveat"><b>These percentages are not one run.</b> __PROV_WARNING__</p>
<div class="chart">__CASCADE__</div>
<p class="sub"><b>Removed over the branch&rsquo;s history:</b></p>
<ul class="sub">__REMOVED__</ul>

<h3>Where each resolver&rsquo;s knowledge comes from</h3>
<p>Nothing is hand-written per signature &mdash; every source derives from one
of a handful of external artifacts.</p>
<div class="chart">__SOURCES__</div>
<p class="sub">Three consequences of that shape drive most of the results
below:</p>
<ul class="sub">__CONSEQUENCES__</ul>
</section>

<div class="rule"><b>Do not rank across regimes.</b> __RULE__</div>

__PANELS__

<section class="card">
<h2>Entity-normalisation arms</h2>
<p>Parsed live from the <code>validation_report_*.md</code> each arm wrote, so
these cannot drift from the artifacts. All are regime D on the same 361 rows
&mdash; but they are <b>not one comparison</b>: effort 19 added the alert
corpus and moved the baseline from 36.6% / 22.2% to 40.2% / 28.7%, so arms
either side of it are scored against different references and are grouped
accordingly below.</p>
<p>The finding survives the split, and is the point of the panel: ten-plus ways
of rewriting the input text &mdash; two NER models, two marker schemes, five
merge rules, three replacement styles &mdash; and <b>not one of them beats its
own baseline</b>. The best lands inside the noise band; the rest are worse.</p>
__ARMS__
</section>

__ORACLE__
</div>
"""


if __name__ == '__main__':
    main()
