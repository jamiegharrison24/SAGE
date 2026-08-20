"""
Generates a self-contained HTML review dashboard from stored baseline records.

Regenerated from the JSON rather than hand-maintained, so it cannot drift from the
numbers it displays, and so it grows as the run matrix grows -- a record with no
perturbation cells yet simply renders without that panel instead of showing a
stale one.

Design notes, since they are decisions rather than defaults:

- The page tokens are the *chart* tokens. Surfaces, inks and the accent are the
  same validated palette the figures use, so chrome and data share one colour
  system instead of two that nearly agree.
- The categorical slots are assigned in fixed order and never cycled, and every
  series is direct-labelled. Two of the four slots sit below 3:1 contrast on the
  light surface, where direct labels are the required relief rather than a nicety.
- Status colour is reserved for the verdict strip and never reused for a series.
- Everything is inlined: no CDN, no webfont, no external asset. The artifact CSP
  blocks them, and a silent font fallback would be worse than the system stack.
"""

import json
import os

# Validated categorical palette: light and dark steps of the same four hues.
SERIES_LIGHT = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']
SERIES_DARK = ['#3987e5', '#d95926', '#199e70', '#c98500']

FAMILY_LABELS = {
    'false_positives': 'False positives',
    'duplicates': 'Duplicate bursts',
    'missing_alerts': 'Dropped alerts',
    'missing_episodes': 'Dropped episodes',
}

STAGE_GROUPS = [
    ('Reading alerts', ['Reading alerts']),
    ('Episode building', ['Converting to episodes', 'Converting to episode sequences',
                          'Breaking into sub-sequences and generating traces']),
    ('Learning S-PDFA', ['Learning S-PDFA']),
    ('Rendering AGs', ['Making alert-driven AGs']),
]


def _payload(record):
    """
    Reduces a full record to just what the page draws.

    Keeps the page small: the stored record carries per-graph detail and formula
    strings for every metric, most of which the dashboard summarises rather than
    lists.

    @param record: a loaded result record
    @return: a JSON-serialisable dict for the page
    """
    reference = record.get('reference') or {}
    aggregate = reference.get('attack_graphs', {}).get('aggregate', {})
    distribution = reference.get('attack_graphs', {}).get('distribution', {})
    graphs = reference.get('attack_graphs', {}).get('per_graph') or []
    compression = reference.get('compression', {})
    timing = reference.get('timing', {})
    alerts = reference.get('alerts', {}).get('totals', {})
    training = reference.get('perplexity', {}).get('training') or {}
    heldout = reference.get('perplexity', {}).get('heldout') or {}

    perturbations = []
    for cell in record.get('perturbations') or []:
        if 'distortion' not in cell:
            continue
        perturbations.append({
            'family': cell['spec']['family'],
            'rate': cell['spec']['rate'],
            'seed': cell['spec']['seed'],
            'jaccard': cell['distortion']['graph_jaccard'],
            'gained': cell['distortion']['n_ags_gained'],
            'lost': cell['distortion']['n_ags_lost'],
            'n_attack_graphs': cell['metrics'].get('n_attack_graphs'),
            'perplexity': cell.get('perplexity'),
        })

    sweeps = []
    for cell in record.get('sweeps') or []:
        if 'elasticity' not in cell:
            continue
        sweeps.append({
            'parameter': cell['spec']['parameter'],
            'value': cell['spec']['value'],
            'baseline_value': cell['spec']['baseline_value'],
            'jaccard': cell['distortion']['graph_jaccard'],
            'n_attack_graphs': cell['metrics'].get('n_attack_graphs'),
            'total_nodes': cell['metrics'].get('total_nodes'),
            'elasticity': {k: v for k, v in cell['elasticity'].items() if v is not None},
        })

    stages = []
    claimed = {n for _, names in STAGE_GROUPS for n in names}
    recorded = timing.get('stages') or []
    for label, names in STAGE_GROUPS:
        stages.append({'label': label,
                       'seconds': sum(s['seconds'] for s in recorded
                                      if s['stage'] in names)})
    other = sum(s['seconds'] for s in recorded if s['stage'] not in claimed)
    if other:
        stages.append({'label': 'Other', 'seconds': other})

    return {
        'dataset': record.get('dataset'),
        'commit': record.get('measured_commit'),
        'created_at': record.get('created_at'),
        'host': record.get('host'),
        'schema_version': record.get('schema_version'),
        'notes': record.get('notes') or [],
        'argv': reference.get('argv') or [],
        'environment': record.get('environment') or {},
        'iana': record.get('iana') or {},
        'aggregate': aggregate,
        'distribution': distribution,
        'compression': {k: v for k, v in compression.items()
                        if not isinstance(v, dict)},
        'compression_inputs': compression.get('inputs', {}),
        'formulas': reference.get('attack_graphs', {}).get('formulas', {}),
        'compression_formulas': compression.get('formulas', {}),
        'alerts': alerts,
        'counter_agrees': reference.get('alerts', {}).get('counter_agrees_with_sage'),
        'timing': {'wall_clock_seconds': timing.get('wall_clock_seconds'),
                   'alert_throughput': timing.get('alert_throughput'),
                   'stages': stages},
        'perplexity': {
            'training': {k: training.get(k) for k in
                         ('perplexity', 'alpha', 'alphabet_size', 'n_traces',
                          'n_symbols', 'n_scored_outcomes', 'unresolved_fraction',
                          'oov_events', 'prob_source', 'resolved_by_model')},
            'heldout': {k: heldout.get(k) for k in
                        ('perplexity', 'n_train', 'n_test', 'split_seed',
                         'unresolved_fraction', 'absent_because')},
        },
        'repeats': record.get('repeats') or {},
        'perturbations': perturbations,
        'sweeps': sweeps,
        'graph_points': [{'nodes': g['nodes'],
                          'reach': g.get('reachability_density'),
                          'density': g.get('density'),
                          'branching': g.get('branching_factor'),
                          'linearity': g.get('path_linearity'),
                          'objective': g.get('objective')}
                         for g in graphs if g.get('reachability_density') is not None],
    }


def render(records):
    """
    Renders the dashboard HTML for one or more dataset records.

    @param records: the loaded result records
    @return: the HTML document body (no <html>/<head>/<body> wrapper)
    """
    payloads = [_payload(record) for record in records]
    # Embedded in a <script type="application/json"> block, so the only character
    # that can break out is '<' (a literal "</script>" inside any string value
    # would end the block early). Emitting it as the JSON escape < keeps the
    # document intact and parses back to an identical string.
    data = json.dumps(payloads).replace('<', '\\u003c')
    return _TEMPLATE.replace('__DATA__', data) \
                    .replace('__SERIES_LIGHT__', json.dumps(SERIES_LIGHT)) \
                    .replace('__SERIES_DARK__', json.dumps(SERIES_DARK)) \
                    .replace('__FAMILY_LABELS__', json.dumps(FAMILY_LABELS))


def write(baseline_directory, output_path, datasets=None):
    """
    Loads records and writes the dashboard.

    @param baseline_directory: directory holding metrics-<dataset>.json
    @param output_path: the .html file to write
    @param datasets: dataset keys, or None for whatever is present
    @return: the output path
    @raise FileNotFoundError: if no records were found
    """
    if datasets is None:
        datasets = sorted(name[len('metrics-'):-len('.json')]
                          for name in os.listdir(baseline_directory)
                          if name.startswith('metrics-') and name.endswith('.json'))
    records = []
    for dataset in datasets:
        path = os.path.join(baseline_directory, 'metrics-{}.json'.format(dataset))
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as handle:
                records.append(json.load(handle))
    if not records:
        raise FileNotFoundError('No metrics-*.json found in {}'.format(baseline_directory))

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as handle:
        handle.write(render(records))
    return output_path


_TEMPLATE = r"""<title>SAGE Baseline Evidence</title>
<style>
:root {
  color-scheme: light;
  --page:        #f4f5f6;
  --surface:     #fcfcfb;
  --raised:      #ffffff;
  --ink:         #0b0b0b;
  --ink-2:       #52514e;
  --muted:       #898781;
  --rule:        #e1e0d9;
  --axis:        #c3c2b7;
  --accent:      #2a78d6;
  --accent-soft: rgba(42,120,214,0.10);
  --good:        #0ca30c;
  --warning:     #fab219;
  --critical:    #d03b3b;
  --ring:        rgba(11,11,11,0.10);
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page:        #0d0d0d;
    --surface:     #1a1a19;
    --raised:      #201f1e;
    --ink:         #ffffff;
    --ink-2:       #c3c2b7;
    --muted:       #898781;
    --rule:        #2c2c2a;
    --axis:        #383835;
    --accent:      #3987e5;
    --accent-soft: rgba(57,135,229,0.14);
    --good:        #0ca30c;
    --warning:     #fab219;
    --critical:    #d03b3b;
    --ring:        rgba(255,255,255,0.10);
    --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page:        #0d0d0d;
  --surface:     #1a1a19;
  --raised:      #201f1e;
  --ink:         #ffffff;
  --ink-2:       #c3c2b7;
  --muted:       #898781;
  --rule:        #2c2c2a;
  --axis:        #383835;
  --accent:      #3987e5;
  --accent-soft: rgba(57,135,229,0.14);
  --good:        #0ca30c;
  --warning:     #fab219;
  --critical:    #d03b3b;
  --ring:        rgba(255,255,255,0.10);
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500;
}

* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--page);
  color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 40px 24px 88px; }
.mono {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.86em;
}
h1 { font-size: 28px; line-height: 1.2; margin: 0; text-wrap: balance; letter-spacing: -0.015em; }
h2 { font-size: 17px; margin: 0 0 4px; letter-spacing: -0.005em; }
h3 { font-size: 13px; margin: 0; color: var(--ink-2); font-weight: 600; }
p  { margin: 0; color: var(--ink-2); }
a  { color: var(--accent); }

.eyebrow {
  font-size: 11px; letter-spacing: 0.10em; text-transform: uppercase;
  color: var(--muted); font-weight: 600; margin: 0 0 10px;
}

header { display: flex; flex-direction: column; gap: 14px; margin-bottom: 28px; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 20px; align-items: center; }
.meta span { color: var(--muted); font-size: 12.5px; }
.meta b { color: var(--ink-2); font-weight: 500; }

.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 11px; border-radius: 999px; font-size: 12.5px; font-weight: 500;
  border: 1px solid var(--ring); background: var(--surface); color: var(--ink-2);
}
.chip .dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.chip.good     .dot { background: var(--good); }
.chip.warning  .dot { background: var(--warning); }
.chip.critical .dot { background: var(--critical); }
.chip.neutral  .dot { background: var(--muted); }

.banner {
  display: flex; gap: 12px; align-items: flex-start;
  border: 1px solid var(--ring); border-left: 3px solid var(--warning);
  background: var(--surface); border-radius: 10px; padding: 14px 16px;
}
.banner .label {
  font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--warning); font-weight: 700; flex: none; padding-top: 2px;
}
.banner ul { margin: 0; padding-left: 18px; color: var(--ink-2); font-size: 13.5px; }
.banner li + li { margin-top: 6px; }

section { margin-top: 34px; }
.section-head { margin-bottom: 14px; }

.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); gap: 12px; }
.tile {
  background: var(--surface); border: 1px solid var(--ring); border-radius: 10px;
  padding: 14px 15px; display: flex; flex-direction: column; gap: 3px;
}
.tile .k { font-size: 11.5px; color: var(--muted); letter-spacing: 0.02em; }
.tile .v { font-size: 25px; font-weight: 600; letter-spacing: -0.02em; line-height: 1.15; }
.tile .s { font-size: 11.5px; color: var(--muted); }
.tile.is-flagged { border-left: 3px solid var(--warning); }

.panels { display: grid; grid-template-columns: repeat(auto-fit, minmax(430px, 1fr)); gap: 16px; }
.panel {
  background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
  padding: 18px 18px 14px; min-width: 0;
}
.panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 2px; }
.panel .why { font-size: 12.5px; color: var(--muted); margin: 6px 0 14px; }
.chart { width: 100%; overflow-x: auto; }
svg { display: block; max-width: 100%; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 10px; }
.legend .item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink-2); }
.legend .sw { width: 10px; height: 10px; border-radius: 2px; flex: none; }

.tbl { width: 100%; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: right; padding: 7px 10px; border-bottom: 1px solid var(--rule); }
th:first-child, td:first-child { text-align: left; }
th { color: var(--muted); font-weight: 600; font-size: 11.5px; letter-spacing: 0.04em; text-transform: uppercase; }
td { color: var(--ink-2); font-variant-numeric: tabular-nums; }
td.name { color: var(--ink); }
tbody tr:last-child td { border-bottom: none; }

details.deriv { margin-top: 8px; }
details.deriv summary {
  cursor: pointer; font-size: 12px; color: var(--accent); list-style: none;
  display: inline-flex; align-items: center; gap: 5px; padding: 3px 0;
}
details.deriv summary::-webkit-details-marker { display: none; }
details.deriv summary::before { content: "\25B8"; font-size: 9px; transition: transform .15s; }
details.deriv[open] summary::before { transform: rotate(90deg); }
details.deriv .body {
  margin-top: 8px; padding: 12px 14px; border-radius: 8px;
  background: var(--accent-soft); font-size: 12.5px; color: var(--ink-2);
}
details.deriv .body p + p { margin-top: 9px; }
details.deriv code { color: var(--ink); }

#tip {
  position: fixed; pointer-events: none; opacity: 0; transition: opacity .1s;
  background: var(--raised); color: var(--ink); border: 1px solid var(--ring);
  border-radius: 8px; padding: 8px 11px; font-size: 12.5px; z-index: 50;
  box-shadow: 0 6px 22px rgba(0,0,0,0.16); max-width: 260px;
}
#tip .t { font-weight: 600; margin-bottom: 3px; }
#tip .r { color: var(--ink-2); font-variant-numeric: tabular-nums; }
.hit { cursor: crosshair; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
@media (max-width: 720px) {
  .wrap { padding: 28px 16px 64px; }
  h1 { font-size: 23px; }
  .panels { grid-template-columns: 1fr; }
}
</style>

<div class="wrap">
  <header>
    <p class="eyebrow">Task A3 &middot; Regression reference</p>
    <h1>SAGE baseline evidence</h1>
    <div class="meta" id="meta"></div>
    <div class="chips" id="chips"></div>
  </header>

  <div id="caveats"></div>

  <section>
    <div class="section-head">
      <h2>Headline</h2>
      <p>What the pinned commit scores. Every figure here is derived from run artifacts, not from instrumented pipeline code.</p>
    </div>
    <div class="tiles" id="tiles"></div>
    <details class="deriv">
      <summary>How compression is defined, and why the numerator is what it is</summary>
      <div class="body" id="compression-deriv"></div>
    </details>
  </section>

  <section>
    <div class="section-head">
      <h2>Model evaluation</h2>
      <p>Does the pipeline hold up under repetition, imperfect input, and parameter change?</p>
    </div>
    <div class="panels">
      <div class="panel">
        <div class="panel-head"><h3>Robustness under alert noise</h3></div>
        <p class="why">Alerts are corrupted before SAGE reads them, so the whole chain is exercised. 1.0 means the attack-graph set is unchanged.</p>
        <div class="chart" id="c-robust"></div>
        <div class="legend" id="l-robust"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Parameter sensitivity</h3></div>
        <p class="why">Elasticity: relative change in a metric per relative change in the parameter. A bar at zero means the parameter moves nothing.</p>
        <div class="chart" id="c-sens"></div>
        <div class="legend" id="l-sens"></div>
      </div>
    </div>
  </section>

  <section>
    <div class="section-head">
      <h2>Attack graph structure</h2>
      <p>Per-graph, not dataset means &mdash; graph sizes span an order of magnitude and an average hides it.</p>
    </div>
    <div class="panels">
      <div class="panel">
        <div class="panel-head"><h3>Density vs graph size</h3></div>
        <p class="why">Why density is measured by reachability: edge density tracks graph size rather than traversability.</p>
        <div class="chart" id="c-density"></div>
        <div class="legend" id="l-density"></div>
        <details class="deriv">
          <summary>The two density formulas</summary>
          <div class="body" id="density-deriv"></div>
        </details>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Where the runtime goes</h3></div>
        <p class="why">Recovered by timestamping stdout stage banners, with no modification to sage.py.</p>
        <div class="chart" id="c-runtime"></div>
        <div class="legend" id="l-runtime"></div>
      </div>
    </div>
  </section>

  <section>
    <div class="section-head"><h2>Perplexity</h2>
      <p>Recorded for comparability with Nadeem et al., not as a quality claim &mdash; the paper itself argues it carries little weight for graph construction.</p>
    </div>
    <div class="panel">
      <div class="tbl"><table id="perp"></table></div>
      <details class="deriv">
        <summary>How the probabilities are obtained, and what the unresolved fraction means</summary>
        <div class="body" id="perp-deriv"></div>
      </details>
    </div>
  </section>

  <section>
    <div class="section-head"><h2>Reproduction</h2></div>
    <div class="panel">
      <div class="tbl"><table id="env"></table></div>
    </div>
  </section>
</div>

<div id="tip" role="status" aria-live="polite"></div>

<script id="viz-data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('viz-data').textContent);
const FAMILY = __FAMILY_LABELS__;
const D = DATA[0] || {};

/* Returns the CSS variable rather than its resolved hex, so marks follow the
   theme live. Resolving to hex at render time bakes one theme's palette into the
   SVG attributes, and a viewer toggling theme afterwards would keep light-mode
   series colours on a dark ground. */
function series(i){ return 'var(--s'+(i+1)+')'; }
function num(v, d){ if (v===null||v===undefined) return '\u2014';
  return typeof v==='number' ? v.toLocaleString(undefined,{maximumFractionDigits:d===undefined?2:d}) : String(v); }
function esc(s){ const e=document.createElement('div'); e.textContent=s==null?'':String(s); return e.innerHTML; }
const NS='http://www.w3.org/2000/svg';
function el(n,a){ const x=document.createElementNS(NS,n); for(const k in (a||{})) x.setAttribute(k,a[k]); return x; }

/* ---- tooltip ---- */
const tip=document.getElementById('tip');
function showTip(evt,title,rows){
  tip.innerHTML='<div class="t">'+esc(title)+'</div>'+rows.map(r=>'<div class="r">'+esc(r)+'</div>').join('');
  tip.style.opacity='1';
  const b=tip.getBoundingClientRect();
  let x=evt.clientX+14, y=evt.clientY-10;
  if(x+b.width>window.innerWidth-8) x=evt.clientX-b.width-14;
  if(y+b.height>window.innerHeight-8) y=window.innerHeight-b.height-8;
  tip.style.left=x+'px'; tip.style.top=Math.max(8,y)+'px';
}
function hideTip(){ tip.style.opacity='0'; }
function hit(node,title,rows){
  node.classList.add('hit');
  node.addEventListener('mousemove',e=>showTip(e,title,rows));
  node.addEventListener('mouseleave',hideTip);
}

/* ---- header ---- */
function header(){
  const m=document.getElementById('meta');
  const argv=(D.argv||[]).slice(1).join(' ');
  m.innerHTML=[
    '<span>Dataset <b class="mono">'+esc(D.dataset)+'</b></span>',
    '<span>Commit <b class="mono">'+esc((D.commit||'').slice(0,10))+'</b></span>',
    '<span>Schema v<b>'+esc(D.schema_version)+'</b></span>',
    '<span>Recorded <b>'+esc((D.created_at||'').slice(0,10))+'</b></span>'
  ].join('');

  const chips=[];
  const partial=(D.notes||[]).some(n=>n.startsWith('PARTIAL RUN'));
  chips.push(partial
    ? {c:'warning', t:'Partial run \u2014 not a citable baseline'}
    : {c:'good', t:'Full-dataset run'});
  if(D.counter_agrees===true) chips.push({c:'good',t:'Alert counts agree with SAGE'});
  else if(D.counter_agrees===false) chips.push({c:'critical',t:'Alert counts disagree with SAGE'});
  const rp=D.repeats&&D.repeats.exact_match;
  if(rp){
    const norm=rp.ag_dot_match_rate_normalised, raw=rp.ag_dot_match_rate_raw;
    if(norm===1&&raw===1) chips.push({c:'good',t:'Deterministic (byte-identical)'});
    else if(norm===1) chips.push({c:'good',t:'Deterministic modulo tooltip order'});
    else chips.push({c:'critical',t:'Not deterministic \u2014 needs tolerance bands'});
  } else chips.push({c:'neutral',t:'Determinism unverified (no repeats yet)'});
  chips.push({c:'neutral',t:(D.perturbations||[]).length+' noise cells \u00b7 '+(D.sweeps||[]).length+' sweep cells'});
  document.getElementById('chips').innerHTML=chips.map(c=>
    '<span class="chip '+c.c+'"><span class="dot"></span>'+esc(c.t)+'</span>').join('');

  if((D.notes||[]).length){
    document.getElementById('caveats').innerHTML=
      '<div class="banner"><div class="label">Read first</div><ul>'+
      D.notes.map(n=>'<li>'+esc(n)+'</li>').join('')+'</ul></div>';
  }
  return argv;
}
const ARGV=header();

/* ---- tiles ---- */
(function tiles(){
  const a=D.aggregate||{}, t=D.timing||{}, al=D.alerts||{}, p=(D.perplexity||{}).training||{};
  const ho=(D.perplexity||{}).heldout||{};
  const prim=D.compression&&D.compression.primary;
  const items=[
    {k:'Raw records', v:num(al.raw_records,0)},
    {k:'Attack graphs', v:num(a.n_attack_graphs,0), s:num(a.n_victims,0)+' victims \u00b7 '+num(a.n_objectives,0)+' objectives'},
    {k:'Compression', v:num(D.compression&&D.compression[prim],0), s:'records per graph'},
    {k:'AG nodes', v:num(a.total_nodes,0), s:num(a.unique_nodes,0)+' unique'},
    {k:'Perplexity (train)', v:num(p.perplexity,2), s:'alphabet '+num(p.alphabet_size,0)},
    {k:'Perplexity (held-out)', v:num(ho.perplexity,2),
     s:ho.unresolved_fraction!=null?(Math.round(ho.unresolved_fraction*100)+'% unresolved'):'not scored',
     flag: ho.unresolved_fraction!=null && ho.unresolved_fraction>0.2},
    {k:'Runtime', v:num(t.wall_clock_seconds,1)+'s', s:num(t.alert_throughput,0)+' rec/s'},
  ];
  document.getElementById('tiles').innerHTML=items.map(i=>
    '<div class="tile'+(i.flag?' is-flagged':'')+'"><span class="k">'+esc(i.k)+
    '</span><span class="v">'+esc(i.v)+'</span>'+
    (i.s?'<span class="s">'+esc(i.s)+'</span>':'')+'</div>').join('');

  const cf=D.compression_formulas||{}, ci=D.compression_inputs||{};
  document.getElementById('compression-deriv').innerHTML=
    '<p>Primary ratio <code class="mono">'+esc(prim)+'</code> = '+
    num(ci.raw_records,0)+' \u00f7 '+num(ci.n_attack_graphs,0)+' = <b>'+num(D.compression&&D.compression[prim],1)+'</b>.</p>'+
    '<p>'+esc(cf[prim]||'')+'</p>'+
    '<p>Attack graphs are counted as distinct (victim, objective) pairs, not files \u2014 the output directory holds a .dot, .png and .svg per graph.</p>';
})();

/* ---- robustness ---- */
(function robustness(){
  const cells=D.perturbations||[];
  const host=document.getElementById('c-robust');
  if(!cells.length){ host.innerHTML='<p class="why">No noise-injection cells recorded yet.</p>'; return; }

  const fams=Object.keys(FAMILY).filter(f=>cells.some(c=>c.family===f));
  const rates=[...new Set(cells.map(c=>c.rate))].sort((a,b)=>a-b);
  const W=520,H=250,L=44,R=118,T=14,B=38;
  const x=r=>L+(rates.length<2?0:(r-rates[0])/(rates[rates.length-1]-rates[0])*(W-L-R));
  const y=v=>T+(1-v)*(H-T-B);
  const svg=el('svg',{viewBox:'0 0 '+W+' '+H,width:W,height:H,role:'img'});

  [0,0.25,0.5,0.75,1].forEach(g=>{
    svg.appendChild(el('line',{x1:L,x2:W-R,y1:y(g),y2:y(g),stroke:'var(--rule)','stroke-width':1}));
    const tx=el('text',{x:L-8,y:y(g)+4,'text-anchor':'end','font-size':10,fill:'var(--muted)'});
    tx.textContent=g.toFixed(2); svg.appendChild(tx);
  });
  rates.forEach(r=>{
    const tx=el('text',{x:x(r),y:H-B+16,'text-anchor':'middle','font-size':10,fill:'var(--muted)'});
    tx.textContent=Math.round(r*100)+'%'; svg.appendChild(tx);
  });
  const ax=el('text',{x:(L+W-R)/2,y:H-6,'text-anchor':'middle','font-size':10.5,fill:'var(--muted)'});
  ax.textContent='noise rate'; svg.appendChild(ax);

  fams.forEach((f,i)=>{
    const col=series(i);
    const pts=rates.map(r=>{
      const vs=cells.filter(c=>c.family===f&&c.rate===r).map(c=>c.jaccard).sort((a,b)=>a-b);
      if(!vs.length) return null;
      return {r, med:vs[Math.floor(vs.length/2)], lo:vs[0], hi:vs[vs.length-1], n:vs.length};
    }).filter(Boolean);
    if(!pts.length) return;

    if(pts.some(p=>p.hi>p.lo)){
      const band=pts.map(p=>x(p.r)+','+y(p.hi)).join(' ')+' '+
                 pts.slice().reverse().map(p=>x(p.r)+','+y(p.lo)).join(' ');
      svg.appendChild(el('polygon',{points:band,fill:col,opacity:0.14}));
    }
    svg.appendChild(el('polyline',{points:pts.map(p=>x(p.r)+','+y(p.med)).join(' '),
      fill:'none',stroke:col,'stroke-width':2,'stroke-linejoin':'round','stroke-linecap':'round'}));
    pts.forEach(p=>{
      const c=el('circle',{cx:x(p.r),cy:y(p.med),r:4.5,fill:col,stroke:'var(--surface)','stroke-width':1.5});
      hit(c,FAMILY[f]+' @ '+Math.round(p.r*100)+'%',
        ['graph Jaccard '+p.med.toFixed(3),'range '+p.lo.toFixed(3)+'\u2013'+p.hi.toFixed(3),p.n+' seed(s)']);
      svg.appendChild(c);
    });
    const last=pts[pts.length-1];
    const lb=el('text',{x:x(last.r)+9,y:y(last.med)+3.5,'font-size':10.5,fill:'var(--ink-2)'});
    lb.textContent=FAMILY[f]; svg.appendChild(lb);
  });

  host.appendChild(svg);
  document.getElementById('l-robust').innerHTML=fams.map((f,i)=>
    '<span class="item"><span class="sw" style="background:'+series(i)+'"></span>'+esc(FAMILY[f])+'</span>').join('');
})();

/* ---- sensitivity ---- */
(function sensitivity(){
  const cells=D.sweeps||[];
  const host=document.getElementById('c-sens');
  if(!cells.length){ host.innerHTML='<p class="why">No sweep cells recorded yet.</p>'; return; }

  const metrics=['n_attack_graphs','total_nodes','total_edges','unique_nodes'];
  const labels={n_attack_graphs:'Attack graphs',total_nodes:'Nodes',total_edges:'Edges',unique_nodes:'Unique nodes'};
  const params=[...new Set(cells.map(c=>c.parameter))].sort();
  const agg={};
  params.forEach(p=>{ agg[p]={};
    metrics.forEach(m=>{
      const vs=cells.filter(c=>c.parameter===p&&c.elasticity[m]!=null).map(c=>Math.abs(c.elasticity[m]));
      agg[p][m]=vs.length?vs.reduce((a,b)=>a+b,0)/vs.length:0;
    });
  });
  const max=Math.max(0.001,...params.flatMap(p=>metrics.map(m=>agg[p][m])));

  const W=520,L=104,R=54,rowH=30,barH=11,T=8;
  const H=T+metrics.length*rowH+30;
  const svg=el('svg',{viewBox:'0 0 '+W+' '+H,width:W,height:H,role:'img'});
  const x=v=>L+v/max*(W-L-R);

  metrics.forEach((m,mi)=>{
    const yBase=T+mi*rowH+rowH/2;
    const lb=el('text',{x:L-10,y:yBase+4,'text-anchor':'end','font-size':11,fill:'var(--ink-2)'});
    lb.textContent=labels[m]; svg.appendChild(lb);
    params.forEach((p,pi)=>{
      const v=agg[p][m], col=series(pi);
      const yy=yBase-barH-1+pi*(barH+2);
      const w=Math.max(1.5,x(v)-L);
      const r=el('rect',{x:L,y:yy,width:w,height:barH,rx:3,fill:col});
      hit(r,'-'+p+' \u00b7 '+labels[m],['|elasticity| '+v.toFixed(3),
        v<0.02?'parameter moves this metric essentially not at all':'mean over swept values']);
      svg.appendChild(r);
      const t=el('text',{x:L+w+6,y:yy+barH-1.5,'font-size':10,fill:'var(--muted)'});
      t.textContent=v.toFixed(2); svg.appendChild(t);
    });
  });
  svg.appendChild(el('line',{x1:L,x2:L,y1:T,y2:T+metrics.length*rowH,stroke:'var(--axis)','stroke-width':1}));
  const ax=el('text',{x:(L+W-R)/2,y:H-8,'text-anchor':'middle','font-size':10.5,fill:'var(--muted)'});
  ax.textContent='|elasticity|  (mean over swept values)'; svg.appendChild(ax);
  host.appendChild(svg);

  document.getElementById('l-sens').innerHTML=params.map((p,i)=>
    '<span class="item"><span class="sw" style="background:'+series(i)+'"></span><span class="mono">-'+esc(p)+'</span></span>').join('');
})();

/* ---- density vs size ---- */
(function density(){
  const pts=D.graph_points||[];
  const host=document.getElementById('c-density');
  if(!pts.length){ host.innerHTML='<p class="why">No per-graph detail recorded.</p>'; return; }

  const W=520,H=260,L=44,R=16,T=14,B=42;
  const maxN=Math.max(...pts.map(p=>p.nodes));
  const x=n=>L+n/maxN*(W-L-R), y=v=>T+(1-v)*(H-T-B);
  const svg=el('svg',{viewBox:'0 0 '+W+' '+H,width:W,height:H,role:'img'});

  [0,0.25,0.5,0.75,1].forEach(g=>{
    svg.appendChild(el('line',{x1:L,x2:W-R,y1:y(g),y2:y(g),stroke:'var(--rule)','stroke-width':1}));
    const t=el('text',{x:L-8,y:y(g)+4,'text-anchor':'end','font-size':10,fill:'var(--muted)'});
    t.textContent=g.toFixed(2); svg.appendChild(t);
  });
  [['reach','Reachability density',0],['density','Edge density',1]].forEach(([key,label,slot])=>{
    const col=series(slot);
    pts.forEach(p=>{
      if(p[key]==null) return;
      const c=el('circle',{cx:x(p.nodes),cy:y(p[key]),r:3.4,fill:col,opacity:0.65,
        stroke:'var(--surface)','stroke-width':1});
      hit(c,p.objective||'attack graph',[label+' '+p[key].toFixed(3),p.nodes+' nodes']);
      svg.appendChild(c);
    });
  });
  const ax=el('text',{x:(L+W-R)/2,y:H-8,'text-anchor':'middle','font-size':10.5,fill:'var(--muted)'});
  ax.textContent='nodes per attack graph  (n = '+pts.length+')'; svg.appendChild(ax);
  host.appendChild(svg);

  document.getElementById('l-density').innerHTML=
    '<span class="item"><span class="sw" style="background:'+series(0)+'"></span>Reachability density</span>'+
    '<span class="item"><span class="sw" style="background:'+series(1)+'"></span>Edge density</span>';

  const f=D.formulas||{};
  document.getElementById('density-deriv').innerHTML=
    '<p><b>Reachability density</b> \u2014 '+esc(f.reachability_density||'')+'</p>'+
    '<p><b>Edge density</b> \u2014 '+esc(f.density||'')+'</p>';
})();

/* ---- runtime ---- */
(function runtime(){
  const stages=((D.timing||{}).stages||[]).filter(s=>s.seconds>0);
  const host=document.getElementById('c-runtime');
  if(!stages.length){ host.innerHTML='<p class="why">No stage timing recorded.</p>'; return; }
  const total=stages.reduce((a,s)=>a+s.seconds,0);

  const W=520,H=96,L=0,T=26,barH=34;
  const svg=el('svg',{viewBox:'0 0 '+W+' '+H,width:W,height:H,role:'img'});
  let cx=L;
  stages.forEach((s,i)=>{
    const w=s.seconds/total*(W-L);
    const col=i<4?series(i):'var(--muted)';
    const r=el('rect',{x:cx+(i?1:0),y:T,width:Math.max(0,w-(i?1:0)),height:barH,fill:col,
      rx:i===0||i===stages.length-1?4:0});
    hit(r,s.label,[s.seconds.toFixed(2)+' s',(s.seconds/total*100).toFixed(1)+'% of runtime']);
    svg.appendChild(r);
    if(w>52){
      const t=el('text',{x:cx+w/2,y:T+barH+15,'text-anchor':'middle','font-size':10,fill:'var(--muted)'});
      t.textContent=Math.round(s.seconds/total*100)+'%'; svg.appendChild(t);
    }
    cx+=w;
  });
  const cap=el('text',{x:0,y:14,'font-size':11,fill:'var(--ink-2)'});
  cap.textContent=total.toFixed(1)+' s total'; svg.appendChild(cap);
  host.appendChild(svg);

  document.getElementById('l-runtime').innerHTML=stages.map((s,i)=>
    '<span class="item"><span class="sw" style="background:'+(i<4?series(i):'var(--muted)')+'"></span>'+
    esc(s.label)+'</span>').join('');
})();

/* ---- perplexity ---- */
(function perp(){
  const t=(D.perplexity||{}).training||{}, h=(D.perplexity||{}).heldout||{};
  const rb=t.resolved_by_model||{};
  const rows=[
    ['Perplexity', num(t.perplexity,3), h.perplexity!=null?num(h.perplexity,3):'\u2014'],
    ['Traces scored', num(t.n_traces,0), h.n_test!=null?num(h.n_test,0):'\u2014'],
    ['Symbols', num(t.n_symbols,0), '\u2014'],
    ['Alphabet', num(t.alphabet_size,0), '\u2014'],
    ['Unresolved steps', t.unresolved_fraction!=null?(t.unresolved_fraction*100).toFixed(1)+'%':'\u2014',
      h.unresolved_fraction!=null?(h.unresolved_fraction*100).toFixed(1)+'%':'\u2014'],
    ['Resolved via main model', num(rb.main,0), '\u2014'],
    ['Resolved via sinks model', num(rb.sinks,0), '\u2014'],
  ];
  document.getElementById('perp').innerHTML=
    '<thead><tr><th>Measure</th><th>Training</th><th>Held-out</th></tr></thead><tbody>'+
    rows.map(r=>'<tr><td class="name">'+esc(r[0])+'</td><td>'+esc(r[1])+'</td><td>'+esc(r[2])+'</td></tr>').join('')+
    '</tbody>';

  const pct=h.unresolved_fraction!=null?Math.round(h.unresolved_fraction*100):null;
  document.getElementById('perp-deriv').innerHTML=
    '<p>Probabilities come from FlexFringe\u2019s own exported counts (<code class="mono">'+esc(t.prob_source||'\u2014')+
    '</code>): <code class="mono">P(sym|state) = (trans_counts[sym] + \u03b1) / (total_paths + total_final + \u03b1\u00b7n_outcomes)</code>, with \u03b1 = '+
    num(t.alpha,2)+'. The end-of-trace event is scored, not skipped.</p>'+
    '<p>Traversal tries the main model first, then the sinks model \u2014 '+
    (rb.main&&rb.sinks?Math.round(rb.sinks/(rb.main+rb.sinks)*100)+'% of steps resolve via sinks, so scoring against the main model alone would be wrong.':'')+'</p>'+
    (pct!==null?'<p><b>Held-out caveat.</b> '+pct+'% of held-out steps fall off the model entirely and are scored against a uniform fallback rather than skipped (skipping would flatter the model). At that level the held-out figure is substantially a statement about the fallback policy, and is <b>not</b> comparable like-for-like with the training figure. The defensible reading is the coverage claim: '+pct+'% of unseen behaviour has no path through the learned model.</p>':'');
})();

/* ---- environment ---- */
(function env(){
  const e=D.environment||{}, i=D.iana||{};
  const rows=[
    ['Command','python '+ARGV],
    ['Commit',D.commit],
    ['Host',D.host],
    ['OS',e.os],['CPU cores',e.cpu_count],['Python',e.python_version],
    ['Graphviz',e.graphviz_version],['glibc',e.glibc_version],
    ['FlexFringe SHA-256',e.flexfringe_sha256],
    ['IANA CSV SHA-256',i.sha256],
  ].filter(r=>r[1]!=null&&r[1]!=='');
  document.getElementById('env').innerHTML='<tbody>'+rows.map(r=>
    '<tr><td class="name">'+esc(r[0])+'</td><td style="text-align:left" class="mono">'+esc(r[1])+'</td></tr>'
  ).join('')+'</tbody>';
})();
</script>
"""
