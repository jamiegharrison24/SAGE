# Findings — CPTC-2017 baseline

> Part of the [documentation index](README.md). Companion to
> [`BASELINE_METRICS.md`](BASELINE_METRICS.md), which defines *how* every number
> here was computed and records the reproduction commands. This document is what
> the numbers **mean**.

**Scope.** One dataset: CPTC-2017, 47,876 alerts across 10 teams, measured at
`baseline-v1` (`20aa5ed`). Full 61-cell matrix — reference, 5 repeats, 48
noise-injection cells, 7 parameter-sweep cells. CPTC-2018 and CCDC are not yet
run, so nothing here is claimed to generalise.

---

## 1. SAGE is fragile to false positives, and to nothing else

Graph Jaccard against the reference run (1.000 = an unchanged set of attack
graphs), median of 3 seeds:

| Perturbation | 1% | 5% | 10% | 20% |
|---|---:|---:|---:|---:|
| **False positives** | **0.832** | **0.534** | **0.366** | **0.264** |
| Duplicate bursts | 1.000 | 0.981 | 0.963 | 0.981 |
| Dropped alerts | 1.000 | 0.972 | 0.936 | 0.835 |
| Dropped episodes | 1.000 | 0.981 | 0.963 | 0.907 |

Three of the four noise families barely register. Duplicate bursts are absorbed
almost perfectly. Losing alerts — even contiguous blocks amounting to whole
attack steps — degrades the output gently and predictably.

False positives are different in kind. At 10% injection **only 37% of the
attack-graph set survives**; at 20%, 26%. Even 1% is measurable, at a point where
every other family is still at exactly 1.000.

### The mechanism: fabrication, not corruption

The raw counts show what is happening. Injected alerts are sampled from the
observed signature distribution, so they map to genuine attack stages through the
same lookup real alerts use — nothing filters them. They form new episodes, which
produce new `(victim, objective)` pairs, which produce **additional attack
graphs**.

So SAGE under false positives does not produce visibly degraded graphs. It
produces *more* graphs, which look normal. That is the harder failure mode: an
analyst is handed extra plausible attack narratives with no signal that they are
fictional.

### Why this matters for the paper

The introduction motivates the entire project on SOC alert streams being
dominated by false positives. The evaluation shows that is precisely the input
SAGE handles worst.

⚠️ **This contradicts *Anticipated Results***, which currently states an
expectation of resilience to false positives. That section needs revising. A
paper that predicts X and then measures not-X reads as a failure to check;
reporting the measured result as a finding reads as rigour.

### Why this matters for Contribution A

The damage runs entirely through the **signature → attack-stage mapping**:
whether a spurious alert is treated as a real attack step. That mapping is
exactly what the MITRE ATT&CK work replaces.

A3 therefore hands Contribution A a testable hypothesis: *does an ATT&CK-based
mapping change how false positives propagate into attack graphs?* It could go
either way — a broader mapping might classify more junk as genuine stages and
make the problem worse. Either result is publishable, and the framework can now
measure it directly by re-running this same noise grid against the new mapping.

**Open question for supervision:** should robustness-under-noise be promoted to a
headline evaluation axis for Contribution A, rather than a baseline property?

---

## 2. `-t` (deduplication threshold) has no effect

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

A **tenfold** change in the deduplication window produces an identical
attack-graph set — same 104 graphs, same 1,885 nodes, Jaccard exactly 1.000,
elasticity 0.000 on every metric. This is the full corpus, not a sample.

`-w` behaves as expected: wider aggregation windows merge more alerts per
episode, so node counts fall monotonically (1,995 → 1,765) while the graph count
barely moves.

The methodology section motivates sensitivity analysis on the grounds that the
S-PDFA is "governed by manually tuned parameters, including deduplication
threshold and episode aggregation window". On this dataset, one of those two is
not tuning anything.

**Likely explanation:** `-t` only removes alerts identical in source IP,
destination IP, *both* ports and signature within the window — a narrow enough
condition that whatever survives it is re-merged by episode aggregation anyway.

**Caveat:** CPTC-2018 has a very different alert profile (69% of its records are
cloud-metadata noise filtered before analysis), so this must be re-checked there
before being stated as a general property.

---

## 3. Perplexity measures less than it appears to

| Measure | Training | Held-out |
|---|---:|---:|
| Perplexity | 13.478 | 40.27 |
| Traces scored | 1,102 | 220 |
| **Unresolved steps** | **0.0%** | **32.6%** |

Held-out scoring splits traces 80/20 before learning (seed 42), trains a separate
model on the 80%, and scores the unseen 20%.

The 40.27 figure should **not** be read as "three times worse than training".
A third of held-out steps have *no path through the model at all* — traversal
falls off the automaton and the step is scored against a uniform fallback rather
than skipped (skipping would flatter the model). At that level, the number is
substantially a statement about the fallback policy.

**The defensible claim is the coverage one:** roughly a third of unseen attack
behaviour is not representable in the learned automaton.

This is concrete evidence for a position the paper already takes — that
perplexity "carries little weight" for a task that is not prediction. Worth using
as evidence rather than asserting it.

---

## 4. The pipeline is fully deterministic

Five identical repeat runs, compared at artifact level:

| Check | Result |
|---|---|
| Attack graph `.dot` files | **104 / 104 byte-identical** (raw bytes) |
| Trace file, both model JSONs | identical |
| All structural metrics | stdev **0** |
| Training perplexity | stdev **0** |
| Wall-clock runtime | stdev 3.7 s — the only thing that varies |

Unglamorous but valuable: regression testing can use exact equality, `--check`
needs no tolerance bands, and any future difference is a genuine difference
rather than noise.

Note this holds on **raw** bytes only because `PYTHONHASHSEED=0` is pinned on
every run — at `baseline-v1` the attack-graph tooltip list is joined from an
unsorted `set`.

---

## 5. Reference values

| Metric | Value |
|---|---:|
| Raw records | 47,876 |
| Attack graphs | 104 |
| Victims / objectives | 36 / 25 |
| Nodes (total / unique) | 1,885 / 326 |
| Edges | 3,024 |
| Compression (records per graph) | 460.3 |
| Training perplexity | 13.478 |
| Runtime | 97.5 s |
| Throughput | 491 records/s |

Runtime is dominated by Graphviz rendering (~89%); the alert processing and
automaton learning together take about 10 seconds.

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
al.'s published figures.** This should be stated explicitly wherever the two are
placed side by side.

---

## 7. Open decisions

1. **Graph density definition — needs a ruling before the baseline is frozen.**
   The paper gives no formula, only the intent that density "captures how easily
   an attacker can traverse the network". Textbook edge density turns out to
   measure graph *size* rather than traversability (correlation with node count
   **−0.79** across the 104 baseline graphs). Reachability density — the fraction
   of ordered state pairs the attacker can actually reach — is size-independent
   (**+0.17**) and is the literal reading of the stated intent. Both are recorded
   in every result, so the choice is reversible without re-running; but one must
   be named as *the* density.

2. **Revise *Anticipated Results*** to match the measured false-positive result.

3. **Decide Contribution A's evaluation framing** — whether robustness under
   noise becomes a headline axis (see §1).

---

## 8. What is not yet known

- **Everything above is one dataset.** CPTC-2018 and CCDC are not yet run.
  The false-positive result and the inert `-t` both need confirming there.
- CPTC-2018 in particular has a very different profile — 69% of its records are
  filtered as cloud-metadata noise before analysis.
- No comparison against any alternative approach; this is a baseline of SAGE
  against itself.

---

## Reproducing these numbers

```bash
python -m evaluation run --dataset cptc-2017 --worktree ../SAGE-baseline \
    --repeats 5 --heldout --perturb --sweep
```

Full record: `baseline/metrics-cptc-2017.json` (`schema_version: 1`).
Generated summary: `baseline/report-cptc-2017.md`.
Figures: `figures/fig-*-cptc-2017.pdf`.
Interactive dashboard: `baseline/dashboard.html`.

To verify the baseline still holds after a change:

```bash
python -m evaluation check --dataset cptc-2017 --worktree ../SAGE-baseline
```

Exits non-zero on any structural regression.
