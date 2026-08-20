# Baseline Evaluation Metrics (Task A3)

> Part of the [documentation index](README.md). Read [`BASELINE.md`](BASELINE.md) first —
> it pins *which commit* is the baseline; this document records *what that commit scores*.

This is the regression reference for the SAGE extension project. Every later
contribution — the MITRE ATT&CK mapping layer, the evaluation framework itself —
is measured against the numbers recorded here.

The machine-readable records live in `baseline/metrics-<dataset>.json`
(`schema_version: 1`). This document is the human-readable view. **The JSON is
authoritative**; if the two ever disagree, regenerate this document with
`python -m evaluation report`.

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

> **Status: not yet populated with full-dataset runs.** The framework is complete
> and verified end to end, but the numbers below are placeholders until the full
> matrix has been run. Values recorded from `--timerange`-limited runs are marked
> `PARTIAL RUN` in their JSON record and must not be cited.

| Dataset | Raw records | AGs | Nodes | Compression | Perplexity (train) | Perplexity (held-out) | Runtime |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cptc-2017` | 47,876 | — | — | — | — | — | — |
| `cptc-2018` | 331,554 | — | — | — | — | — | — |
| `ccdc` | 1,052,281 | — | — | — | — | — | — |

Alert counts above are measured and final; the remaining columns await the full runs.

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

**Provisional finding:** two independent runs of the same configuration produced
**identical values for all 16 structural and perplexity metrics**; only wall-clock
runtime differed (1.6%). This is why `schema.TOLERANCES` sets structural
tolerances to exactly `0.0`. The 5-repeat matrix with artifact-level byte
comparison is what will confirm it.

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

**Provisional finding — SAGE is markedly sensitive to false positives.** A 10%
false-positive injection produced:

| Metric | Clean | +10% FP | Change |
|---|---:|---:|---:|
| Attack graphs | 72 | 116 | +61% |
| Objectives | 20 | 41 | +105% |
| Total nodes | 748 | 1,196 | +60% |
| Training perplexity | 11.73 | 19.50 | +66% |

Injecting one spurious alert in ten roughly doubles the number of distinct
objectives an analyst is shown. If this holds on the full datasets it is a
substantive result for the paper's robustness claim, and it cuts against the
expectation of resilience stated in *Anticipated Results*.

### Sensitivity analysis

A one-at-a-time sweep of the two parameters the paper names — `-t`
(deduplication threshold) and `-w` (episode aggregation window) — around **each
dataset's own defaults**, since CPTC-2018's documented baseline is `-t 2.0 -w 200`
rather than SAGE's defaults. Each cell reports the same distortion measures plus
an **elasticity** per metric (relative change in metric ÷ relative change in
parameter), so the paper can state which parameter the model is most sensitive to.

**Provisional finding — the two parameters are not remotely equal:**

| Parameter | Values | Attack graphs | Graph Jaccard vs reference |
|---|---|---:|---:|
| `-t` | 0.5, 1.0, 2.0, 5.0 | 72, 72, 72, 72 | 1.000 |
| `-w` | 50, 100, 150, 200, 300 | 73, 74, 72, 71, 70 | 0.959 – 0.973 |

**`-t` had no effect at all.** A tenfold change in the deduplication window (0.5s
to 5.0s) produced byte-identical attack graph sets — elasticity 0.00 on every
metric. `-w` produces a small, monotone effect: wider aggregation windows yield
slightly fewer, smaller graphs.

If this survives the full-dataset runs it is worth stating plainly, because the
paper motivates sensitivity analysis on the grounds that the S-PDFA "is governed
by manually tuned parameters". At least on CPTC-2017, one of those two parameters
appears not to be doing anything. **Caveat:** a 2-hour slice contains few
duplicate alerts for `-t` to filter, so this must be re-checked on the full
capture before it is claimed.

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
