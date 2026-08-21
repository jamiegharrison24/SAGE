# Baseline Evaluation Metrics (Task A3)

> Part of the [documentation index](README.md). Read [`BASELINE.md`](BASELINE.md) first —
> it pins *which commit* is the baseline; this document records *what that commit scores*.

This is the regression reference for the SAGE extension project. Every later
contribution — the MITRE ATT&CK mapping layer, the evaluation framework itself —
is measured against the numbers recorded here.

The machine-readable records live in `baseline/metrics-<dataset>.json`
(`schema_version: 1`). **The JSON is authoritative** — it is what `--check` diffs
against, and every number below is derived from it.

This document is written and maintained by hand: it carries the reasoning,
caveats and definitions that a generated report cannot. The *generated* per-run
summary is a separate file, `baseline/report-<dataset>.md`, produced by
`python -m evaluation report --dataset <name> --markdown baseline/report-<name>.md`.
Do not point that command at this file — it would overwrite the commentary.

## Glossary

Terms used throughout this document, grouped by where they come from. If you are
reading a number in `baseline/metrics-*.json` and are unsure what it counts, start
here.

### SAGE pipeline terms

| Term | Meaning |
|---|---|
| **Alert** | One IDS (Suricata) detection: a timestamp, source and destination IP and port, and a signature string. The raw input. |
| **Signature** | The human-readable rule name Suricata attaches to an alert, e.g. `ET POLICY Python-urllib/ Suspicious User Agent`. SAGE maps signatures to attack stages via a hardcoded lookup — the thing the MITRE work replaces. |
| **`mcat`** | *Micro attack stage*. The attack step an alert represents, as an integer whose digit count encodes severity: 1 digit = low (scanning), 2 = medium (enabler), 3 = high (exploitation/objective). |
| **`mserv`** | The targeted service, resolved from the destination port via the IANA port-service table. |
| **Episode** | A burst of alerts of the same `mcat` between one attacker and one victim, aggregated over a sliding window. One episode = one attacker *action*. |
| **Subsequence** | A run of consecutive episodes cut at severity drops, representing one distinct attack attempt. Subsequences shorter than 3 episodes are discarded. |
| **Trace** | A subsequence written as FlexFringe input: a reversed sequence of `mcat|mserv` symbols. Reversal is what makes the learned automaton a *suffix* automaton. |
| **Symbol** | One `mcat|mserv` pair, e.g. `vulnD|mysql`. The alphabet is the set of distinct symbols across all traces. |
| **S-PDFA** | *Suffix Probabilistic Deterministic Finite Automaton* — the model FlexFringe learns from the traces. States capture attacker progress; edges carry transition probabilities. |
| **FlexFringe** | The external automaton-learning binary that produces the S-PDFA. A Linux ELF binary, so it runs under WSL on Windows. |
| **Sink / sink state** | A state FlexFringe did not merge into the main model because too little data supported it. Sinks live in a separate model file, and traversal falls back to them when the main model has no matching transition. **38% of scored steps resolve this way**, so sinks are not an edge case. |
| **Objective** | A high-severity attack stage treated as an attacker goal. Attack graphs are generated per (victim, objective) pair. |
| **Victim** | The destination IP an attack graph is drawn for. |
| **Attack graph (AG)** | The final output: a directed graph, per victim per objective, whose nodes are attacker actions and whose edges are transitions between them, one edge per attacker. |
| **`-t`** | The duplicate-filter window in seconds. Identical alerts within `-t` of each other collapse to one. |
| **`-w`** | The episode aggregation window in seconds — how wide a burst of alerts is grouped into a single episode. |

### Evaluation terms

| Term | Meaning |
|---|---|
| **Reference run** | The single canonical run of a dataset at its documented parameters. Everything else is measured against it. |
| **Cell** | One run in the matrix — a reference, a repeat, a perturbation, or a sweep point. Each has its own output directory and can be resumed independently. |
| **Run matrix** | The full set of cells for a dataset: reference + repeats + perturbations + sweeps. |
| **Artifact-driven** | Metrics are derived from the files a run leaves behind (`.txt` traces, model JSONs, `.dot` graphs) plus its stdout — never by importing pipeline code. This is what lets one harness measure both `baseline-v1` and later branches. |
| **Tolerance** | How far a metric may move before `--check` calls it a regression. Structural counts are exact (`0.0`); runtime is recorded but never fatal. |
| **Jaccard index** | Overlap between two sets: `|A ∩ B| / |A ∪ B|`. 1.0 = identical, 0.0 = disjoint. Used for node sets, edge sets and the set of (victim, objective) graphs. |
| **Distortion** | How far a perturbed or swept run moved from the reference — Jaccard plus per-metric deltas plus graphs gained and lost. |
| **Elasticity** | Relative change in a metric ÷ relative change in the parameter that caused it. Makes `-t` and `-w` comparable despite different units. Near zero = the parameter does not move that metric. |
| **Perturbation family** | One kind of injected noise: false positives, duplicate bursts, dropped alerts, or dropped episodes. |
| **Rate (ρ)** | The proportion of alerts a perturbation adds or removes. |
| **Output variance** | Spread of each metric across repeat runs of identical configuration. |
| **Exact-artifact match** | Whether repeat runs produced byte-identical output files — reported raw and after normalising `.dot` tooltip ordering. |
| **Determinism** | Whether identical inputs give identical outputs. If not, fixed reference values are unusable and every tolerance needs a band instead. |

### Metric terms

| Term | Meaning |
|---|---|
| **Raw records** | Every JSON object in the alert files, including non-alert events. The paper's "raw alerts" convention. |
| **Raw alerts** | Records surviving the `event_type == 'alert'` and dataset filters (CPTC bad-IP, "Not Suspicious Traffic"). |
| **Post-dedup alerts** | What remains after the `-t` duplicate window. Scraped from SAGE's own stdout rather than recomputed, so it cannot drift from what SAGE actually did. |
| **Compression ratio** | Raw records per generated attack graph — the paper's core utility claim, i.e. how much the analyst's reading load shrinks. |
| **Branching factor** | `edges / nodes`. How much an attack path fans out. Note this is the paper's definition, not the conventional mean out-degree. |
| **Path linearity** | `longest path (in edges) / total edges`. Near 1.0 = one long chain; low = a bushy graph with many short branches. |
| **Simplicity** | `nodes / edges` — the reciprocal of branching factor. Kept only for comparability with Nadeem et al. |
| **Edge density** | `distinct edges / (V(V-1))`. The textbook measure; confounded by graph size here (see the density section). |
| **Reachability density** | Fraction of ordered node pairs the attacker can get between over paths of *any* length. The headline density: 0.5 means an attacker at a random state can reach half the others. |
| **Self-loop** | An edge from a node to itself, i.e. an attacker repeating the same action against the same service. Real and common in these graphs. |
| **Parallel edges** | Two or more edges between the same node pair, one per attacker. Counted separately so any ratio can be rebuilt on either edge basis. |
| **Perplexity** | How surprised the model is by a sequence: `exp(-mean log P(outcome))`. Lower is better. Roughly "how many equally likely options the model thinks it faces at each step". |
| **Training perplexity** | Scored on the traces the model learned from. Comparable to the original SAGE paper, but it does not test generalisation. |
| **Held-out perplexity** | Traces split 80/20 before learning; the model is trained on the 80% and scored on the unseen 20%. Needs a second FlexFringe run and a separate model. |
| **Alphabet** | The set of distinct symbols the model can emit. |
| **Add-α smoothing** | Adding a small constant (α = 0.1) to every outcome count so an unobserved symbol gets a small probability instead of zero — which would make perplexity infinite. |
| **Unresolved step** | A step where traversal falls off the model entirely (no matching transition in either the main or sinks model). Scored against a uniform distribution rather than skipped, because skipping would flatter the model. |
| **Unresolved fraction** | Share of scored outcomes that were unresolved. Near zero on training traces; high on held-out traces, where it means the reported perplexity is substantially a statement about the fallback policy rather than the model. |
| **OOV** | *Out of vocabulary* — a symbol in the test set that the training set never contained. |
| **Alert throughput** | `raw records / wall-clock seconds`. |

## What "regression reference" means operationally

A stored number is only a reference if a later run can be checked against it
mechanically. That is what `--check` does:

```bash
python -m evaluation check --dataset cptc-2017 --worktree ../SAGE-baseline
```

It re-runs the dataset, recomputes every metric, and diffs against the stored
record — exiting **non-zero** if anything moved outside tolerance. It is verified
to work in both directions: it passes against a freshly recorded baseline, and
fails (13 metrics) when fed a run whose alerts were deliberately perturbed.

Tolerances live in `evaluation/schema.py`. Structural counts and perplexity are
**exact** (tolerance `0.0`). Runtime and throughput are recorded and reported as
drift but never fail a check, because they are hardware-dependent and would
otherwise make the check fail on a different machine for reasons unrelated to a
regression.

## Reproducing these numbers

```bash
# One-time: alerts ship gzipped
find alerts/ -type f -name '*.gz' | xargs gunzip

# Check out the baseline into a separate worktree — never modify it in place
git worktree add ../SAGE-baseline baseline-v1

# Record a dataset (reference + 5 repeats + held-out perplexity)
python -m evaluation run --dataset cptc-2017 --worktree ../SAGE-baseline \
    --repeats 5 --heldout --markdown docs/BASELINE_METRICS.md
```

Three things are pinned so that a rerun is actually comparable:

- **`PYTHONHASHSEED=0`** on every run. At `baseline-v1` the AG tooltip join is
  unsorted over a `set`, and Python randomises string hashing per process.
- **The IANA port-service CSV.** SAGE downloads it at runtime and derives `mserv`
  labels from it, so an upstream republish shifts AG structure for reasons that
  have nothing to do with the code. The harness snapshots it once and serves the
  pinned copy via a generated `sitecustomize.py` on `PYTHONPATH` — the baseline
  tree is never patched. Its SHA-256 is recorded in every result.
- **The split seed** (`42`) for held-out perplexity.

## Headline results

> **Status: all three datasets recorded.** CPTC-2017 and CPTC-2018 ran the full
> 61-cell matrix; CCDC ran a reduced 13-cell matrix without noise injection (see
> [`FINDINGS.md`](FINDINGS.md) for why).

| Dataset | Raw records | AGs | Nodes | Compression | Perplexity (train) | Perplexity (held-out) | Runtime |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cptc-2017` | 47,876 | 104 | 1,885 | 460 | 13.478 | 40.27 | 97.5 s |
| `cptc-2018` | 331,554 | 75 | 1,283 | 4,421 | 9.419 | 35.90 | 85.2 s |
| `ccdc` | 1,052,281 | 72 | 306 | 14,615 | 4.838 | 6.67 | 90.3 s |

Held-out perplexity is **not** comparable to the training figure on the CPTC
datasets — 32.6% and 39.5% of scored steps respectively fall off the model
entirely (see the perplexity section). CCDC is the exception at 6.7%.

Note that runtime is nearly flat across a 22x range of input size, because it is
dominated by Graphviz rendering rather than alert processing. Throughput rises
from 491 to 11,659 records/second accordingly.

For what these numbers **mean** — what replicated across datasets and what did
not — see [`FINDINGS.md`](FINDINGS.md).

### Determinism: confirmed on all three datasets

Five identical repeat runs per dataset, compared at artifact level:

| Dataset | Attack graph `.dot` files | Traces / models | Structural metrics |
|---|---|---|---|
| `cptc-2017` | **104 / 104 byte-identical** | identical | stdev **0** |
| `cptc-2018` | **75 / 75 byte-identical** | identical | stdev **0** |
| `ccdc` | **72 / 72 byte-identical** | identical | stdev **0** |

Training perplexity is stdev **0** on every dataset. Wall-clock runtime is the
only thing that varies (±3.7 s on CPTC-2017).

The `.dot` files match on **raw bytes**, which they would not without
`PYTHONHASHSEED=0` pinned: at `baseline-v1` the tooltip signature list is joined
from an unsorted `set`. The pin is what makes byte-level comparison meaningful
here.

This is the evidence behind the exact-`0.0` structural tolerances in
`schema.TOLERANCES`. Fixed reference values are safe; tolerance bands are not
needed.

## Metric definitions

The paper defines some of these loosely and one not at all, so the formula
actually used is recorded in every JSON record alongside the value it produced. A
number without its definition cannot be reproduced, only re-obtained by luck.

### Graph structure

| Metric | Formula | Status |
|---|---|---|
| Branching factor | `edges_total / nodes` | **From the paper**, verbatim. Note this is *not* the conventional mean out-degree. |
| Path linearity | `longest_path_edges / edges_total` | **From the paper**, verbatim. |
| Simplicity | `nodes / edges_total` | Reciprocal of branching factor. Included only for comparability with Nadeem et al. |
| **Reachability density** | `reachable_ordered_pairs / (nodes * (nodes - 1))` | **HEADLINE density.** Chosen; see below. |
| Edge density | `edges_simple_no_loops / (nodes * (nodes - 1))` | Textbook directed density, retained for comparability. |

#### Why density is measured by reachability

The paper gives no formula for density. It states only the intent: density
*"captures how easily an attacker can traverse the network"*. Two candidates were
implemented and both are recorded in every result; the choice of which to headline
is argued rather than assumed.

**Edge density** — `E / (V(V-1))` — is the textbook answer, but measured against
the 104 real CPTC-2017 baseline attack graphs it does not measure traversability.
It measures graph size:

| Graph size | Edge density | Reachability density |
|---|---:|---:|
| 3–10 nodes | 0.182 | 0.529 |
| 10–20 nodes | 0.092 | 0.516 |
| 20–35 nodes | 0.055 | 0.536 |
| 35–50 nodes | 0.038 | 0.677 |

`corr(nodes, edge_density) = −0.79`, against `corr(nodes, reachability_density) =
+0.17`. Attack graphs are sparse, so as `V` grows the `V(V-1)` denominator grows
quadratically while the edge count does not. A large attack graph is therefore
scored as "low density" almost mechanically, and comparing edge density across
graphs — or across datasets whose graphs differ in size — largely compares how big
the graphs are.

**Reachability density** counts the ordered state pairs an attacker can actually
get between, following edges of any length:

```
reachability_density = |{(u,v) : u ≠ v, v reachable from u}| / (V · (V-1))
```

Three reasons it is the headline:

1. **It is the literal reading of the paper's sentence.** A value of 0.53 means an
   attacker at a randomly chosen state can reach about half the other states.
   Edge density answers a different question — what fraction of *direct* moves
   exist — which is about local wiring, not traversal.
2. **It is not confounded by size** (+0.17 versus −0.79), so it can be compared
   across graphs and across datasets, which is precisely what a reusable
   evaluation framework needs.
3. **It is not redundant.** The paper already defines branching factor as
   `edges/nodes`; any density that is also an edges-per-node ratio duplicates it.
   Reachability density measures something genuinely additional.

It also discriminates better in practice: across the baseline AGs it spans
0.26–0.89 (median 0.50), where edge density is compressed into 0.03–0.33
(median 0.08).

Both are recorded in every result, so this decision can be revisited by changing
which column the write-up quotes — no re-run required.

⚠️ **Still worth confirming with the author**, since the paper's intent statement
is all there is to go on. If a different definition was meant, both formulas are
recorded and a third can be added without re-running the matrix.

**Edge bases.** SAGE draws one edge per attacker, so parallel edges between the
same node pair are normal, and self-loops occur. Three counts are always stored
so any ratio can be re-derived without a rerun:

- `edges_total` — every edge line; multi-edges preserved, self-loops included
- `edges_simple` — distinct `(tail, head)` pairs
- `edges_simple_no_loops` — distinct pairs where `tail != head`

Branching factor, simplicity and path linearity use `edges_total` (matching
SAGE's own line-counting `_print_simplicity`); density uses
`edges_simple_no_loops`.

### Alert compression

The paper defines compression as *"number of raw alerts divided by number of
generated attack graphs"* but does not say what counts as a raw alert. Its own
dataset section settles it: it cites CCDC-2018 as **1,052,281** alerts, which is
exactly the count of *every record in the file* (the post-filter alert count is
1,033,067). So `raw_records` is the primary numerator.

This matters. On CPTC-2018 the CPTC bad-IP filter discards **69%** of records
(331,554 → 101,571), so the two numerators differ by 3.3× in the headline ratio.
All five variants are recorded:

| Ratio | Definition |
|---|---|
| `raw_records_per_ag` | **PRIMARY.** Every record / attack graphs |
| `raw_alerts_per_ag` | Post-filter alerts / attack graphs |
| `post_dedup_alerts_per_ag` | After the `-t` window / attack graphs |
| `raw_alerts_per_ag_node` | Post-filter alerts / total AG nodes |
| `raw_alerts_per_unique_ag_node` | Post-filter alerts / unique AG nodes |

`n_attack_graphs` counts **distinct `(victim, objective)` pairs**, not files — the
AG directory holds a `.dot`, a `.png` and an `.svg` per graph, so counting files
triples the count.

### Perplexity

```
PP = exp( -(1/N) * Σ log P(outcome_i | state_i) )
```

`N` counts every symbol **plus one end-of-trace event per trace**. The
end-of-trace event is scored, not skipped.

Transition probabilities come from FlexFringe's own exported counts
(`prob_source: "flexfringe_counts"`). Each model node carries
`data.trans_counts`, `total_paths` and `total_final`; verified against the
baseline artifacts, `sum(trans_counts) == total_paths` holds for **all 524
main-model and all 2,310 sink-model nodes** with zero exceptions, so:

```
P(sym | state) = (trans_counts[sym] + α) / (N_state + α · n_outcomes)
P(END | state) = (total_final       + α) / (N_state + α · n_outcomes)
N_state        = total_paths + total_final
n_outcomes     = |alphabet| + 1
α              = 0.1
```

A maximum-likelihood re-derivation from the traces is also implemented, and
reproduces FlexFringe's counts on **all 2,378 states**, so it serves as a
cross-check on the traversal rather than a fallback.

Scoring mirrors `model_learning.traverse`: the main model first, then the sinks
model. This is not a detail — **38% of scored steps resolve via the sinks model**,
so scoring against the main model alone produces plausible-looking nonsense.

Two policies are recorded with every figure:

- **Unresolved steps** (traversal reaches state `-1`) are scored against a uniform
  `1/n_outcomes` rather than skipped, because skipping them flatters the model.
  The fraction is reported as `unresolved_fraction`.
- **Out-of-vocabulary symbols** in held-out scoring widen the outcome space to the
  union of the training and test alphabets, so an unseen symbol gets `α/(…)`
  rather than zero probability.

⚠️ **Training and held-out perplexity are never comparable like-for-like** and are
never averaged. On the training traces `unresolved_fraction` is ~0 and the figure
is a property of the automaton. On held-out traces it can approach half of all
scored outcomes, at which point the number is substantially a statement about the
uniform fallback policy. Records where it exceeds 20% carry an explicit note.

Held-out scoring uses an 80/20 trace-level split with seed `42`, split **before**
FlexFringe is invoked, and therefore requires a **separate FlexFringe run and a
separate model**.

### Computation

- Total wall-clock runtime, and **per-stage** runtime obtained by timestamping
  SAGE's stdout banner lines (no modification to `sage.py`). Stage attribution
  absorbs SAGE's sub-banners (`TEAMS`, `Sub-sequences`), which otherwise steal
  their parent stage's time.
- Alert throughput = `raw_records / wall_clock_seconds`.
- Full hardware and toolchain fingerprint, including the FlexFringe binary's
  SHA-256 and the glibc version (WSL's, on Windows, since that is where the binary
  actually runs).
- Peak RSS is **not** recorded: it needs `psutil`, and adding a dependency beyond
  `requirements.txt` was out of scope. The field is present and null with a stated
  reason rather than silently absent.

## Model evaluation

The paper's model-evaluation dimension has three parts. All three are implemented;
the figures below are from `--timerange 0 2` slices and are **provisional**, but
the method and the shape of the findings are settled.

### Output variance and determinism

Five identical repeat runs per dataset (`--repeats 5`), reporting min / median /
max / stdev per metric, plus an **exact-artifact match rate** over the trace file,
both model JSONs and the AG `.dot` set.

Byte comparison is done twice: raw, and after normalising `.dot` tooltip ordering.
This distinction is not cosmetic. At `baseline-v1` the tooltip signature list is
joined from an unsorted `set`, and Python randomises string hashing per process,
so raw `.dot` bytes differ between runs of identical code. Comparing raw bytes
alone would report SAGE as non-deterministic and — per the framework's own rule —
trigger a recommendation that every downstream reference needs tolerance bands, on
the strength of a formatting artefact.

**Confirmed on the full CPTC-2017 matrix:** five repeats, 104/104 attack graph
`.dot` files byte-identical, every structural and perplexity metric at stdev 0.
See *Determinism: confirmed* above.

### Robustness (noise injection)

Perturbations are applied to the **raw alert files before SAGE reads them**, so
the entire chain — deduplication, episode aggregation, S-PDFA learning, graph
construction — sees the corrupted input. Four families, each at ρ ∈ {1%, 5%, 10%,
20%} with three seeded repetitions:

| Family | What it models |
|---|---|
| `false_positives` | Synthetic alerts drawn from the observed signature distribution, at random times in the capture window |
| `duplicates` | Contiguous alert runs repeated — an IDS re-reporting a burst |
| `missing_alerts` | A random fraction of alerts dropped |
| `missing_episodes` | Contiguous per-attacker-victim time blocks dropped — losing whole attack steps |

The last two are both the paper's "missing attack steps", split because they are
not equally damaging: scattered losses often leave an episode's shape intact,
while a contiguous block can remove an attack step entirely. They are reported
separately, never averaged.

Each perturbed run reports node/edge/graph Jaccard against the reference, AGs
gained and lost, and per-metric deltas.

**Confirmed on the full CPTC-2017 matrix — SAGE is robust to three noise
families and fragile to one.** Graph Jaccard against the reference run, median of
3 seeds (1.000 = an unchanged set of attack graphs):

| Family | 1% | 5% | 10% | 20% |
|---|---:|---:|---:|---:|
| **False positives** | **0.832** | **0.534** | **0.366** | **0.264** |
| Duplicate bursts | 1.000 | 0.981 | 0.963 | 0.981 |
| Dropped alerts | 1.000 | 0.972 | 0.936 | 0.835 |
| Dropped episodes | 1.000 | 0.981 | 0.963 | 0.907 |

Duplicates are absorbed almost perfectly, and losing alerts — even whole
episodes' worth — degrades the output only gently. False positives are different
in kind: at 10% injection **only 37% of the attack-graph set survives**, and at
20% only 26%. Even 1% is measurable, where the other three families are still at
1.000.

This matters for the paper's own framing. The introduction motivates the work by
noting that SOC alert streams are dominated by false positives; the evaluation
shows that is precisely the input SAGE handles worst. It also contradicts the
expectation of resilience stated in *Anticipated Results*, which should be
revised rather than left to disagree with the measured result.

The mechanism is visible in the raw counts: injected alerts map to real attack
stages through the same signature lookup as genuine ones, so they do not get
filtered — they create new episodes, which create new (victim, objective) pairs,
which create additional attack graphs. The distortion is mostly *fabricated*
graphs rather than corrupted ones.

### Sensitivity analysis

A one-at-a-time sweep of the two parameters the paper names — `-t`
(deduplication threshold) and `-w` (episode aggregation window) — around **each
dataset's own defaults**, since CPTC-2018's documented baseline is `-t 2.0 -w 200`
rather than SAGE's defaults. Each cell reports the same distortion measures plus
an **elasticity** per metric (relative change in metric ÷ relative change in
parameter), so the paper can state which parameter the model is most sensitive to.

**Confirmed on the full CPTC-2017 matrix — the two parameters are not remotely
equal:**

| Parameter | Value | Attack graphs | Nodes | Graph Jaccard | Elasticity |
|---|---:|---:|---:|---:|---:|
| *(baseline)* | `-t 1.0 -w 150` | 104 | 1,885 | 1.000 | — |
| `-t` | 0.5 | 104 | 1,885 | **1.000** | 0.000 |
| `-t` | 2.0 | 104 | 1,885 | **1.000** | 0.000 |
| `-t` | 5.0 | 104 | 1,885 | **1.000** | 0.000 |
| `-w` | 50 | 105 | 1,995 | 0.935 | −0.014 |
| `-w` | 100 | 106 | 1,931 | 0.963 | −0.058 |
| `-w` | 200 | 105 | 1,829 | 0.972 | +0.029 |
| `-w` | 300 | 104 | 1,765 | 0.962 | 0.000 |

**`-t` does nothing.** A tenfold change in the deduplication window — 0.5 s to
5.0 s — produces an identical attack-graph set: same 104 graphs, same 1,885
nodes, Jaccard exactly 1.000, elasticity 0.000 on every metric. This is not a
small-sample artefact; it is the full 47,876-alert corpus.

`-w` does have an effect, but a modest and coherent one: wider aggregation
windows merge more alerts per episode, so node counts fall monotonically
(1,995 → 1,765 across the sweep) while the graph count barely moves.

This is worth stating plainly in the paper, because the sensitivity analysis is
motivated on the grounds that the S-PDFA "is governed by manually tuned
parameters, including deduplication threshold and episode aggregation window".
On CPTC-2017, one of those two parameters is not tuning anything. The likely
explanation is that `-t` only removes alerts identical in source, destination,
ports *and* signature within the window, which is a narrow enough condition that
the surviving duplicates are re-merged by episode aggregation regardless. Worth
confirming on CPTC-2018 and CCDC before generalising.

## Known divergences from the paper

| Item | Paper | Measured | Explanation |
|---|---:|---:|---|
| CCDC-2018 records | 1,052,281 | 1,052,281 | Exact match. |
| CPTC-2017 alerts | 43,611 | 47,876 | Paper figure is the **pre-fix 9-team** corpus. Excluding NationalTeam1 (4,274) gives 43,602 — within 9 of the paper. |
| CPTC-2018 records | 330,270 | 331,554 | +1,284 (0.4%). **Unexplained.** |

⚠️ **The CPTC-2017 baseline is not directly comparable to Nadeem et al.'s
published results.** Their figure predates the `NationalTeam1.json__` filename fix
(see [`BASELINE.md`](BASELINE.md), *Dataset integrity*), so it was built from 9
teams; this baseline uses the corrected 10-team corpus.

The two residual CPTC gaps (9 and 1,284 alerts) are reported rather than
reconciled away. As a guard, every run cross-checks this package's independent
alert count against SAGE's own reported tally and records
`counter_agrees_with_sage`; they agree exactly on CPTC-2017 (47,876 both ways).

## A note on perplexity's role

The paper is explicitly dismissive of perplexity — *"as attack graph construction
is not a prediction task, this metric carries little weight"* — and the whole
point of the extended evaluation framework is to go beyond it. Perplexity is
recorded here **for comparability with Nadeem et al.**, not as a quality claim.
Do not let it become the headline.

## Presenting the results

Two outputs, both regenerated from the stored JSON rather than maintained by
hand, so neither can drift from the numbers and both can be re-cut after a
definition changes without re-running SAGE:

```bash
# Publication figures (vector PDF + PNG), sized for an IEEE two-column layout
python -m evaluation report --dataset cptc-2017 --figures figures/

# Self-contained HTML dashboard for review and discussion
python -m evaluation report --dataset cptc-2017 --dashboard baseline/dashboard.html
```

| Figure | Shows |
|---|---|
| `fig-robustness-<dataset>` | Graph Jaccard against noise rate, one line per perturbation family, seed spread as a band |
| `fig-sensitivity-<dataset>` | Per-metric elasticity for `-t` and `-w` |
| `fig-structure-<dataset>` | Per-AG distribution of the structural metrics |
| `fig-runtime` | Per-stage runtime, stacked, across datasets |

Both use one validated categorical palette, assigned in fixed slot order and
never cycled. Two design constraints are deliberate rather than incidental: every
series is **direct-labelled** rather than identified by legend colour alone (two
of the four slots fall below 3:1 contrast on a light surface, where direct labels
are the required relief — and it makes the figures survive greyscale print); and
the ten stage banners are folded into five groups in the runtime figure, because
a categorical palette past its validated slot count stops being distinguishable.

The dashboard leads with a verdict strip — partial vs full run, whether the two
independent alert counts agree, whether determinism has been verified — because
the first question a reader has is whether the numbers can be trusted, not what
they are.

## Framework layout

| Module | Responsibility |
|---|---|
| `runner.py` | Executes the run matrix; timestamps stdout; resumable; guards the worktree |
| `dot_metrics.py` | `.dot` → per-graph raw counts and structural metrics |
| `perplexity.py` | Model loading, probability estimation, training and held-out scoring |
| `alerts.py` | Per-format alert counting and the compression ratios |
| `perturbation.py` | Noise injection and the sweep grids |
| `compare.py` | Distortion between two runs (Jaccard, deltas, elasticity) |
| `collect.py` | Artifacts → a schema record section |
| `flexfringe.py` | Direct FlexFringe invocation, for the held-out model |
| `schema.py` | The versioned record and the regression check |
| `report.py` | JSON → Markdown |
| `figures.py` | JSON → publication figures (PDF + PNG) |
| `dashboard.py` | JSON → self-contained HTML dashboard |
| `__main__.py` | The `run` / `check` / `report` CLI |

The harness is **artifact-driven**: it shells out to `python sage.py … --keep-files`
and derives every metric from the run's stdout and output files. It never imports
the pipeline, because `baseline-v1` predates the `pipeline.py` refactor and
exposes no importable pipeline — an import-based harness could not measure the
very thing it exists to measure. The same harness therefore works unchanged
against the baseline and every later branch.

Unit tests: `python evaluation/tests_evaluation.py`.
