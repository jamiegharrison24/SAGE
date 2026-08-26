# Findings — baseline evaluation across all three datasets

> Part of the [documentation index](README.md). Companion to
> [`BASELINE_METRICS.md`](BASELINE_METRICS.md), which defines *how* every number
> here was computed and records the reproduction commands. This document is what
> the numbers **mean**.

**Scope.** Three datasets measured at `baseline-v1` (`20aa5ed`):

| | CPTC-2017 | CPTC-2018 | CCDC |
|---|---|---|---|
| Matrix | full, 61 cells | full, 61 cells | reduced, 13 cells |
| Reference + 5 repeats | ✅ | ✅ | ✅ |
| Held-out perplexity | ✅ | ✅ | ✅ |
| Noise injection (48 cells) | ✅ | ✅ | ✗ not run |
| `-t`/`-w` sweep | ✅ | ✅ | ✅ |

CCDC's noise grid was skipped deliberately: it is a single 800 MB file, and each
perturbation cell requires loading and deep-copying the whole corpus. The
robustness result therefore rests on two datasets, not three.

---

## Summary: what replicated

| Finding | CPTC-2017 | CPTC-2018 | CCDC | Verdict |
|---|---|---|---|---|
| Byte-level determinism | ✅ 104/104 | ✅ 75/75 | ✅ 72/72 | **replicates (3/3)** |
| `-t` has no meaningful effect | ✅ | ✅ | ✅ | **replicates (3/3)** |
| `-w` shifts graph size monotonically | ✅ | ✅ | ✅ | **replicates (3/3)** |
| False positives are the worst noise family | ✅ | ✅ | — | **replicates (2/2)** |
| *Magnitude* of false-positive damage | severe | moderate | — | **does not replicate** |

The qualitative results hold everywhere they were tested. One quantitative result
does not, and that turns out to be the most interesting part.

---

## 1. False positives are the only noise family that matters — but how much varies by an order of magnitude

Graph Jaccard against the reference run (1.000 = an unchanged set of attack
graphs), median across seeds:

**CPTC-2017**

| Family | 1% | 5% | 10% | 20% |
|---|---:|---:|---:|---:|
| **False positives** | **0.832** | **0.534** | **0.366** | **0.264** |
| Duplicate bursts | 1.000 | 0.981 | 0.963 | 0.981 |
| Dropped alerts | 1.000 | 0.972 | 0.936 | 0.835 |
| Dropped episodes | 1.000 | 0.981 | 0.963 | 0.907 |

**CPTC-2018**

| Family | 1% | 5% | 10% | 20% |
|---|---:|---:|---:|---:|
| **False positives** | **0.974** | **0.914** | **0.768** | **0.685** |
| Duplicate bursts | 1.000 | 1.000 | 1.000 | 1.000 |
| Dropped alerts | 1.000 | 0.974 | 0.961 | 0.924 |
| Dropped episodes | 0.987 | 0.987 | 0.987 | 0.911 |

**What is consistent.** On both datasets, false positives are the only family
that meaningfully degrades the output. Duplicate bursts are absorbed almost or
entirely perfectly — on CPTC-2018, 1.000 at *every* rate, meaning a 20% duplicate
injection changed nothing at all. Missing data, whether scattered alerts or whole
episodes' worth, degrades gently and predictably.

**What is not.** At 20% injection CPTC-2017 retains 26% of its graph set;
CPTC-2018 retains 69%. That is a 2.6× difference in damage from an identical
perturbation.

### The mechanism: fabrication, and why density protects against it

Injected alerts are sampled from the observed signature distribution, so they map
to genuine attack stages through the same lookup real alerts use — nothing
filters them. They form new episodes, which produce new `(victim, objective)`
pairs, which produce **additional attack graphs**. SAGE under false positives does
not produce visibly degraded graphs; it produces *more* graphs, which look normal.

That explains the dataset difference. Compare the evidence density behind each
graph:

| Dataset | Post-filter alerts | Attack graphs | Alerts per graph | Jaccard @ 20% FP |
|---|---:|---:|---:|---:|
| CPTC-2017 | 47,876 | 104 | **460** | **0.264** |
| CPTC-2018 | 101,571 | 75 | **1,354** | **0.685** |
| CCDC | 1,033,067 | 72 | **14,348** | not measured |

The more alerts stand behind each attack graph, the smaller the fraction any
injected alert represents, and the harder it is for noise to manufacture a new
graph. **Hypothesis: false-positive fragility is governed by alerts-per-graph, not
by dataset identity.**

This is a hypothesis on n=2, not a demonstrated law. It is directly testable:
running the noise grid on CCDC (14,348 alerts per graph) predicts markedly *less*
distortion than CPTC-2018. That is a cheap, falsifiable experiment and worth
doing before the claim appears in the paper.

### Why this matters for the paper

The introduction motivates the whole project on SOC alert streams being dominated
by false positives. The evaluation shows that is exactly the input SAGE handles
worst — but that sparse alert environments are far more exposed than dense ones.

⚠️ ***Anticipated Results* currently predicts resilience to false positives** and
should be revised. The honest claim is narrower and more interesting than either
"SAGE is robust" or "SAGE is fragile":

> SAGE is robust to duplicate and missing alerts, but false positives inflate the
> attack-graph set by fabricating plausible graphs. The severity depends on how
> much alert evidence supports each graph, ranging from a 74% loss of graph-set
> overlap on CPTC-2017 to 31% on the denser CPTC-2018.

### Why this matters for Contribution A

The damage runs entirely through the **signature → attack-stage mapping**:
whether a spurious alert is treated as a real attack step. That mapping is
precisely what the MITRE ATT&CK work replaces.

A3 therefore hands Contribution A a testable hypothesis — *does an ATT&CK-based
mapping change how false positives propagate into attack graphs?* It could go
either way: a broader mapping might classify more junk as genuine stages and make
things worse. Either result is publishable, and the framework measures it by
re-running this same noise grid against the new mapping.

**Open question for supervision:** should robustness-under-noise be promoted to a
headline evaluation axis for Contribution A, rather than a baseline property?

---

## 2. `-t` (deduplication threshold) does essentially nothing — on all three datasets

| Dataset | `-t` values swept | Attack graphs | Graph Jaccard |
|---|---|---|---|
| CPTC-2017 | 0.5, 2.0, 5.0 | 104 at every value | **1.000** at every value |
| CPTC-2018 | 0.5, 1.0, 5.0 | 75 at every value | **1.000** at every value |
| CCDC | 0.5, 2.0, 5.0 | 72 at every value | **1.000** at every value |

A tenfold change in the deduplication window leaves the attack-graph set
identical on all three datasets. On CPTC-2017 and CCDC the node counts are
identical too; on CPTC-2018, `-t 0.5` shifts the node count by 2 (1,281 vs
1,283), so the effect is *negligible* rather than mathematically zero. Phrase the
finding as "no meaningful effect" rather than "no effect" — it is more defensible
and survives scrutiny.

`-w` by contrast works everywhere, and its influence varies markedly:

| Dataset | `-w` sweep range | Attack graphs | Nodes | Weakest Jaccard |
|---|---|---|---|---:|
| CPTC-2017 | 50–300 | 104–106 | 1,765–1,995 | 0.935 |
| CPTC-2018 | 50–300 | 72–80 | 1,162–1,453 | 0.934 |
| CCDC | 50–300 | 64–90 | 277–372 | **0.761** |

Node counts fall monotonically as the window widens — more alerts merge into each
episode. CCDC is by far the most `-w`-sensitive.

The methodology section motivates sensitivity analysis on the grounds that the
S-PDFA is "governed by manually tuned parameters, including deduplication
threshold and episode aggregation window". On the evidence, only one of those two
is doing any tuning.

**Likely explanation:** `-t` only removes alerts identical in source IP,
destination IP, *both* ports and signature within the window — a condition narrow
enough that whatever survives it is re-merged by episode aggregation anyway. In
other words, `-w` subsumes `-t`.

---

## 3. Perplexity measures less than it appears to — and its weakness is dataset-dependent

| Dataset | Training | Held-out | **Held-out unresolved** | Unique nodes |
|---|---:|---:|---:|---:|
| CPTC-2017 | 13.478 | 40.270 | **32.6%** | 326 |
| CPTC-2018 | 9.419 | 35.897 | **39.5%** | 242 |
| CCDC | 4.838 | 6.672 | **6.7%** | 121 |

Held-out scoring splits traces 80/20 before learning (seed 42), trains a separate
model on the 80%, and scores the unseen 20%.

The held-out figures for the CPTC datasets should **not** be read as "three to
four times worse than training". A third to two-fifths of held-out steps have *no
path through the model at all* — traversal falls off the automaton and the step is
scored against a uniform fallback rather than skipped (skipping would flatter the
model). At that level the number is substantially a statement about the fallback
policy.

**The defensible claim is the coverage one:** on the CPTC datasets, roughly a
third of unseen attack behaviour is not representable in the learned automaton.

CCDC is the informative contrast. With 1M alerts producing only 121 unique nodes,
its attack structure is highly repetitive, so the model covers almost everything
it later sees — 6.7% unresolved, and a held-out perplexity close to its training
figure. **Held-out quality tracks how much data supports each distinct structure**,
not dataset size as such.

This is concrete evidence for a position the paper already takes — that perplexity
"carries little weight" for a task that is not prediction. Use it as evidence
rather than asserting it.

---

## 4. The pipeline is fully deterministic — on all three datasets

| Dataset | `.dot` files byte-identical | Traces | Models |
|---|---|---|---|
| CPTC-2017 | **104 / 104** | identical | identical |
| CPTC-2018 | **75 / 75** | identical | identical |
| CCDC | **72 / 72** | identical | identical |

Five identical repeat runs each, compared at artifact level. Every structural
metric and training perplexity has stdev **0**; only wall-clock runtime varies.

Unglamorous but valuable: regression testing uses exact equality, `--check` needs
no tolerance bands, and any future difference is a genuine difference.

This holds on **raw** bytes only because `PYTHONHASHSEED=0` is pinned on every
run — at `baseline-v1` the attack-graph tooltip list is joined from an unsorted
`set`.

---

## 5. Reference values

| Metric | CPTC-2017 | CPTC-2018 | CCDC |
|---|---:|---:|---:|
| Raw records | 47,876 | 331,554 | 1,052,281 |
| Post-filter alerts | 47,876 | 101,571 | 1,033,067 |
| Attack graphs | 104 | 75 | 72 |
| Victims | 36 | 12 | 47 |
| Objectives | 25 | 34 | 8 |
| Total nodes | 1,885 | 1,283 | 306 |
| Unique nodes | 326 | 242 | 121 |
| Edges | 3,024 | 2,641 | 327 |
| Compression (records/graph) | 460 | 4,421 | 14,615 |
| Training perplexity | 13.478 | 9.419 | 4.838 |
| Runtime | 97.5 s | 85.2 s | 90.3 s |
| Throughput | 491 rec/s | 3,890 rec/s | 11,659 rec/s |

**Runtime is essentially flat across a 22× range in input size** — 97.5 s for
48 k alerts, 90.3 s for 1.05 M. Throughput therefore rises from 491 to 11,659
records/second. The reason is that runtime is dominated by Graphviz rendering,
which scales with *graph* count and complexity rather than alert count: CCDC
produces only 306 nodes to CPTC-2017's 1,885. The computational-evaluation
section can state that SAGE scales comfortably to million-alert corpora — the
bottleneck is output rendering, not alert processing.

⚠️ **The compression figures will invite a question.** CPTC-2018 looks 10× better
than CPTC-2017, and CCDC 32× better. This is largely a counting convention: the
paper's "raw alerts" numerator counts every record, and 69% of CPTC-2018's
records are cloud-metadata noise discarded before analysis. On post-filter alerts
the ratios are 460 / 1,354 / 14,348. Both are recorded; state which is meant.

---

## 6. Discrepancies against the paper

| Item | Paper | Measured | Status |
|---|---:|---:|---|
| CCDC-2018 records | 1,052,281 | 1,052,281 | exact match |
| CPTC-2017 alerts | 43,611 | 47,876 | **explained** |
| CPTC-2018 records | 330,270 | 331,554 | unexplained (+0.4%) |

The CPTC-2017 gap resolves: excluding NationalTeam1 (4,274 alerts) gives 43,602,
within 9 of the paper's figure. The paper's number is the **pre-fix 9-team
corpus**, inherited from Nadeem et al. and predating the `NationalTeam1.json__`
filename fix.

⚠️ **CPTC-2017 results here are therefore not directly comparable to Nadeem et
al.'s published figures.** State this wherever the two appear side by side.

---

## 7. Open decisions

1. **Graph density definition — needs a ruling before the baseline is frozen.**
   The paper gives no formula, only the intent that density "captures how easily
   an attacker can traverse the network". Textbook edge density measures graph
   *size* rather than traversability (correlation with node count **−0.79** across
   the 104 CPTC-2017 graphs). Reachability density — the fraction of ordered state
   pairs the attacker can actually reach — is size-independent (**+0.17**) and is
   the literal reading of the stated intent. Both are recorded, so the choice is
   reversible without re-running; but one must be named as *the* density.

2. **Revise *Anticipated Results*** to match the measured false-positive result
   (see §1 for suggested wording).

3. **Decide Contribution A's evaluation framing** — whether robustness under
   noise becomes a headline axis.

4. **Run the CCDC noise grid?** It would test the alerts-per-graph hypothesis in
   §1 directly, and turn a two-point observation into a three-point trend. Needs a
   memory-safe perturbation path for an 800 MB single-file corpus.

---

## 8. What is not yet known

- **The robustness result rests on two datasets.** CCDC was not perturbed.
- **The alerts-per-graph hypothesis is n=2.** Plausible and mechanistically
  motivated, but not demonstrated.
- No comparison against any alternative approach; this is SAGE measured against
  itself.
- The +0.4% CPTC-2018 record-count gap against the paper is unexplained.

---

## Reproducing these numbers

```bash
python -m evaluation run --dataset cptc-2017 --worktree ../SAGE-baseline \
    --repeats 5 --heldout --perturb --sweep
python -m evaluation run --dataset cptc-2018 --worktree ../SAGE-baseline \
    --repeats 5 --heldout --perturb --sweep
python -m evaluation run --dataset ccdc --worktree ../SAGE-baseline \
    --repeats 5 --heldout --sweep
```

Records: `baseline/metrics-<dataset>.json` (`schema_version: 1`).
Generated summaries: `baseline/report-<dataset>.md`.
Figures: `figures/fig-*.pdf`. Dashboards: `baseline/dashboard-<dataset>.html`.

To verify a baseline still holds after a change:

```bash
python -m evaluation check --dataset <name> --worktree ../SAGE-baseline
```

Exits non-zero on any structural regression.
