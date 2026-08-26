# Prompt: Task A3 — Baseline Metrics Snapshot + Evaluation Framework

Paste everything below the line into Claude Code, run from the SAGE repo root.

---

## Role and goal

You are implementing **Task A3** of an Engineering Honours project extending SAGE
(IntruSion Alert-driven Attack Graph Extractor).

A3 = *"Record baseline AG structure, perplexity and runtime per dataset as the
regression reference."* Every later change (the MITRE ATT&CK mapping layer, the
evaluation framework itself) is measured against this snapshot, so it must be
frozen, machine-readable, and reproducible.

Scope is the **full evaluation framework**, not just the snapshot: the reference
run, repeat runs for output variance, noise-injection robustness runs, and
parameter sensitivity sweeps.

Do not begin coding until you have read `CLAUDE.md`, `docs/BASELINE.md`, `sage.py`,
`pipeline.py`, `model_learning.py`, `ag_generation.py`, and the scripts in
`test-scripts/`. Then present a short implementation plan for approval.

---

## Verified repo and environment facts

Treat these as established — verify only if something contradicts them.

- **Baseline is tag `baseline-v1`** = commit `20aa5ed99bfee77143d88ffdb19ed43a108810eb`.
  It must never be modified, rewritten, or force-pushed over.
- **`baseline-v1` has no `pipeline.py`.** At that commit SAGE is a monolithic
  `sage.py`. `pipeline.py` (with `PipelineConfig` / `run_pipeline`) only exists on
  the later refactor branch. **Therefore the harness must not import `pipeline` to
  measure the baseline** — it must drive SAGE through its CLI and parse artifacts.
  This also makes the harness work unchanged on both the baseline and future branches.
- `baseline-v1`'s `sage.py` already supports `--keep-files`, `-t`, `-w`, `--dataset`,
  `--timerange`, and prints the same `------ Stage ------` banner lines the current
  code does. Per-stage timing can be recovered by timestamping stdout lines — no
  source modification required.
- **FlexFringe requires GLIBC ≥ 2.38 and GLIBCXX ≥ 3.4.32.** Linux or WSL only;
  it will not run on older distros or native Windows.
- `ag_generation.py` has `_print_simplicity()` (~line 185) computing nodes, edges and
  simplicity, but **the call site is commented out** (~line 332). Do not uncomment it
  in the baseline tree — parse the `.dot` files instead.
- **No perplexity implementation exists** anywhere in this fork or in
  `tudelft-cda-lab/SAGE` upstream. You are writing it from scratch.
- FlexFringe model JSON (`<exp>.txt.ff.final.json`, `<exp>.txt.ff.finalsinks.json`)
  is parsed by `model_learning.load_model` as `machine["edges"]` (`source`, `target`,
  `name`) and `machine["nodes"]` (`id`, `isred`, `isblue`, `issink`). Whether edges
  carry occurrence counts is **unconfirmed** — see the perplexity section.
- Existing helper scripts you should reuse rather than reimplement:
  `test-scripts/stats-ff.sh` (red/blue/white/sink state counts),
  `stats-nodes-ags.sh` (total/unique/sink nodes across an AG dir),
  `stats-sinks-ags.sh`, `compare-ag-dirs.sh`, `diff-nodes.sh`, `diff-edges.sh`.
- Datasets under `alerts/`: `cptc-2017` (10 teams), `cptc-2018` (6 teams),
  `ccdc` (1 file, ~1.05M alerts). Files ship gzipped; decompress first.

---

## Hard constraints

1. **Never modify the `baseline-v1` tree.** Check it out into a separate git worktree
   (`git worktree add ../SAGE-baseline baseline-v1`) and run the harness against it
   from outside. The harness itself lives on a new branch off the current working
   branch.
2. **The harness must be artifact-driven**: it shells out to `python sage.py ...`
   with `--keep-files` and derives every metric from the run's stdout log plus the
   produced `<exp>.txt`, `<exp>.txt.ff.final.json`, `<exp>.txt.ff.finalsinks.json`,
   and `<exp>AGs/*.dot`. No edits to SAGE's pipeline code.
3. **Every number must be reproducible from a recorded command.** Store the exact
   argv, git commit SHA, and environment fingerprint alongside every result.
4. **Do not invent metric definitions silently.** Where the paper leaves a metric
   underspecified (flagged below), implement the stated default, record the chosen
   formula verbatim in the output, and raise it in your summary for review.

---

## Metric set — must cover everything in the paper

The paper (`initial_paper_updated.tex`, §Evaluation Framework) defines three
dimensions. Implement all of them, plus the legacy SAGE metrics needed for
comparability with Nadeem et al.

### A. Model evaluation

**Perplexity — report training and held-out side by side.**

- Per-symbol perplexity: `PP = exp( -(1/N) * Σ log P(symbol_i | state_i) )` where N is
  the total number of symbols scored.
- Include the end-of-trace / final-state probability as a scored event; state
  explicitly in the output whether you did.
- Use add-α smoothing with `α = 0.1` over the observed symbol alphabet; record α.
  Unreachable transitions must not produce infinities — every trace must score.
- **Transition probabilities:** first probe the FlexFringe JSON for per-edge
  occurrence counts. If present, use them and record `"prob_source": "flexfringe_counts"`.
  If absent, re-derive them by maximum likelihood: traverse every training trace
  through the main + sinks model using the same fallback logic as
  `model_learning.traverse`, count `(state, symbol)` occurrences, normalise per state,
  and record `"prob_source": "trace_mle"`. Both paths must be implemented.
- **Training perplexity:** score the same traces the S-PDFA was learned from. This is
  the figure comparable to the original SAGE paper.
- **Held-out perplexity:** 80/20 split of episode subsequences with a **pinned seed
  (`seed = 42`, recorded in output)**, learn on train, score on test. Splitting must
  happen at the trace level, before FlexFringe is invoked. Document that this
  requires a separate FlexFringe run and therefore a separate model.
- Report both, per dataset, and never conflate them in the same field.

**Output variance.** N = 5 repeat runs per dataset with identical configuration.
Report, per metric, the min / median / max / stdev, and separately an **exact-artifact
match rate**: whether `<exp>.txt`, the two model JSONs, and the AG `.dot` set are
byte-identical across repeats (normalise timestamps/paths before comparing). If the
pipeline is not deterministic, every downstream "regression reference" needs
tolerance bands rather than fixed numbers — say so loudly in the summary.

**Robustness (noise injection).** Perturb the *raw alerts* before the pipeline, so the
whole chain is exercised. Three perturbation families from the paper, each at rates
ρ ∈ {1%, 5%, 10%, 20%}, each with 3 seeded repetitions (seeds recorded):

- *False positives*: inject synthetic alerts sampled from the observed signature
  distribution at random timestamps within the capture window.
- *Duplicate sequences*: duplicate randomly chosen alert subsequences.
- *Missing attack steps*: drop a fraction of alerts, and separately drop whole
  episodes' worth of alerts (the more damaging case — implement both and label them).

For each perturbed run, report every structural metric plus **distortion relative to
the reference run**: node-set Jaccard, edge-set Jaccard, count of AGs gained/lost, and
delta in each structural metric. `compare-ag-dirs.sh` / `diff-nodes.sh` /
`diff-edges.sh` give you a starting point but you will likely need a Python
equivalent that emits JSON.

**Sensitivity analysis.** One-at-a-time sweep around each dataset's defaults:

- `-t` (duplicate-filter window) ∈ {0.5, 1.0, 2.0, 5.0}
- `-w` (episode aggregation window) ∈ {50, 100, 150, 200, 300}

Note the 2018 defaults differ (`-t 2.0 -w 200`), so sweeps are relative to each
dataset's own baseline command. Report the same distortion measures as above, and
compute an elasticity per metric (relative change in metric / relative change in
parameter) so the paper can state which parameters the model is most sensitive to.

### B. Results evaluation

**Alert compression ratio** — the paper's core utility claim. It is ambiguously
specified ("raw alerts / number of generated attack graphs"), so record all four and
mark one as primary:

- `raw_alerts / n_attack_graphs` (primary — matches the paper's wording)
- `post_dedup_alerts / n_attack_graphs`
- `raw_alerts / total_ag_nodes`
- `raw_alerts / unique_ag_nodes`

`n_attack_graphs` must count **distinct (victim, objective) graphs**, not files —
`<exp>AGs/` contains both `.png` and `.svg` per graph and would otherwise double-count.

**Graph structural metrics.** Compute **per AG**, then report the distribution
(min/median/mean/max) and the dataset-level aggregate. Always store the raw counts
(`nodes`, `edges`, `longest_path`) so any ratio can be re-derived later without a re-run.

- Branching factor = `edges / nodes` (the paper's definition — keep it, but note in the
  output that this is not the conventional mean out-degree).
- Path linearity = `longest_path_length / total_edges`.
- Graph density — **undefined in the paper (TODO in the source)**. Implement directed
  simple-graph density `E / (V * (V - 1))`, record the formula string in the output,
  and flag it for the author to confirm.
- SAGE "simplicity" = `nodes / edges` (the reciprocal of branching factor). Include it
  purely for comparability with Nadeem et al.
- Multi-edges: AGs draw one edge per attacker, so parallel edges between the same node
  pair are possible. Decide whether to collapse them, apply it consistently, and record
  the choice as a field (`"multiedges": "collapsed" | "preserved"`).

Also carry forward the model-level counts from `stats-ff.sh` (red / blue / white / sink
states) and the sink statistics, plus the per-attacker path counts SAGE already prints
(`total paths`, `unique paths`, `longest`, `shortest`).

### C. Computational evaluation

- Total wall-clock runtime per dataset.
- **Per-stage runtime**, obtained by timestamping SAGE's stdout banner lines
  (`------ Reading alerts ------`, `------ Converting to episodes ------`,
  `------ Learning S-PDFA ------`, `------ Making alert-driven AGs ------`, etc.).
  Do not modify `sage.py` to get this.
- Alert throughput = `raw_alerts / total_runtime_seconds`.
- Peak RSS if cheaply obtainable (e.g. `/usr/bin/time -v`).
- Hardware/environment fingerprint: CPU model, core count, RAM, OS, kernel, glibc
  version, Python version, Graphviz version, FlexFringe binary SHA-256.
- Median of the 5 repeats is the headline figure; report spread alongside.

---

## Known traps you must handle

1. **The IANA port-service mapping is downloaded live at runtime**
   (`load_iana_mapping`). If IANA's CSV changes, `mserv` labels change and AG structure
   shifts for reasons unrelated to the code — destroying the regression reference.
   Snapshot the CSV into the baseline artifacts, record its SHA-256, and provide a
   documented way to run against the pinned copy (e.g. a local HTTP fixture or a
   documented cache path). Do not patch `baseline-v1` to do this; the pinned copy is an
   artifact plus instructions.
2. **Alert counting differs per dataset.** CPTC-2017 alerts are plain Suricata JSON;
   CPTC-2018 files are Splunk-wrapped with the Suricata record inside a `_raw` string
   field, so naive key counting returns zero. Implement a per-dataset counter and unit
   test it.
3. **The paper's CPTC-2017 alert count (43,611) is stale.** It is the pre-fix, 9-team
   figure inherited from the original SAGE paper, from before `NationalTeam1.json__`
   was restored (see `docs/BASELINE.md`, *Dataset integrity*). The corrected corpus is
   ~47.9k alerts across 10 teams, with NationalTeam1 contributing ~4.27k. Report the
   true counts and flag that the baseline is **not** directly comparable to Nadeem et
   al.'s published CPTC-2017 results.
4. **CCDC is ~1.05M alerts.** Full sweeps there are expensive. Order the work
   2017 → 2018 → CCDC, make the run matrix resumable (skip completed cells based on
   existing output), and let the sweep grid be reduced per dataset via config.
5. **AG `.dot` files are deleted unless `--keep-files` is passed.** Every run in the
   matrix needs it, and the harness should fail fast with a clear message if the
   expected artifacts are missing.
6. `<exp>AGs/` may contain stale output from earlier runs. Use a fresh output directory
   per run cell and never write two configurations into the same experiment name.

---

## Deliverables

1. **`evaluation/` package** on a new branch off the current working branch — the seed
   of the paper's reusable evaluation module, so keep it SAGE-agnostic where the paper
   claims reusability. Suggested split (adapt if you have a better structure, and say
   why):
   - `runner.py` — builds and executes the run matrix, timestamps stdout, captures the
     environment fingerprint, resumable
   - `ag_metrics.py` — `.dot` parsing → per-AG raw counts and structural metrics
   - `perplexity.py` — model loading, probability estimation, training + held-out scoring
   - `compression.py` — alert counting per dataset format, compression ratios, throughput
   - `perturbation.py` — noise injection and the parameter sweep grid
   - `compare.py` — distortion measures between two runs (Jaccard, metric deltas)
   - `report.py` — JSON and Markdown emission
   - `schema.py` — a single versioned dataclass/JSON schema for a result record
2. **`baseline/metrics-<dataset>.json`** — one machine-readable record per dataset,
   schema-versioned (`"schema_version": 1`), containing: run metadata (commit SHA,
   argv, seeds, timestamps, environment fingerprint), raw counts, every derived metric
   with its formula string, per-AG detail, and the repeat/perturbation/sweep results.
   Design it so a future run can be diffed programmatically against it.
3. **`docs/BASELINE_METRICS.md`** — human-readable: headline table per dataset,
   environment block, the exact definition of every metric (especially perplexity and
   density), what "regression reference" means operationally, and the reproduction
   commands.
4. **A `--check` mode** that re-runs a dataset and diffs against the stored JSON,
   exiting non-zero on regression outside tolerance. This is what makes the snapshot a
   *reference* rather than a document.
5. **Unit tests** for the pure functions: `.dot` parsing on a small fixture graph,
   perplexity on a hand-computed toy automaton where the expected value is known by
   hand, alert counting for both file formats, and the Jaccard/distortion measures.
6. **A short summary** at the end listing: numbers that differ from the paper, metric
   definitions you had to choose, whether the pipeline is deterministic, and any
   run cells that failed or were skipped.

Update `docs/README.md` to index the new document, and follow the repo's PEP 8 check
(`pycodestyle --ignore=E501,W503,W504`). Do not add dependencies beyond
`requirements.txt` without flagging it.

---

## Acceptance criteria

- Every metric named in the paper's §Evaluation Framework has a recorded baseline value
  for all three datasets, or an explicit, justified reason it is absent.
- Nothing in the `baseline-v1` tree is modified; `git status` in the worktree is clean
  after a full run.
- A second person can reproduce the headline table from `docs/BASELINE_METRICS.md`
  alone, on a clean checkout.
- `--check` passes against the freshly recorded baseline, and demonstrably fails when
  fed a deliberately perturbed run.
- The JSON schema is stable enough that the MITRE-mapping work can emit the same
  record type for direct comparison.

---

## Ask before assuming

Stop and ask rather than guessing if: the FlexFringe JSON turns out to carry
probabilities in a form that contradicts the two estimation paths above; the held-out
split produces degenerate models on the smaller datasets; the pipeline turns out to be
non-deterministic; or the full run matrix looks like it will exceed a reasonable
compute budget on CCDC.
