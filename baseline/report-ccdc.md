# Baseline metrics: `ccdc`

- **Schema version:** 1
- **Measured commit:** `20aa5ed99bfee77143d88ffdb19ed43a108810eb`
- **Recorded:** 2026-08-20T23:50:47.952935+00:00
- **Host:** `Rocinante`

## Reproduction

Run from the SAGE tree at the commit above, with `PYTHONHASHSEED=0`:

```bash
PYTHONHASHSEED=0 python sage.py D:\Projects\SAGE\SAGE\alerts\ccdc ccdc-reference --dataset other --keep-files -t 1.0 -w 150
```

The IANA port-service CSV is fetched live by SAGE and changes AG structure when it changes upstream, so it is pinned for this baseline; see the digest in the environment block below and `evaluation/runner.py` for how the pinned copy is served.

## Headline metrics

| Metric | Value |
|---|---:|
| Raw records | 1,052,281 |
| Raw alerts (post-filter) | 1,033,067 |
| Post-dedup alerts | 515,346 |
| Attack graphs | 72 |
| Victims | 47 |
| Objectives | 8 |
| Total AG nodes | 306 |
| Unique AG nodes | 121 |
| Total AG edges | 327 |
| Compression (raw_records_per_ag) | 14,615.0 |
| Perplexity (training) | 4.838 |
| Perplexity (held-out) | 6.672 |
| Wall clock (s) | 90.3 |
| Throughput (records/s) | 11,659 |

## Per-graph structural distribution

| Metric | n | min | median | mean | max |
|---|---:|---:|---:|---:|---:|
| nodes | 72 | 3 | 4.000 | 4.250 | 8 |
| edges_total | 72 | 2 | 3.000 | 4.542 | 15 |
| longest_path_edges | 72 | 2 | 3.000 | 3.042 | 6 |
| branching_factor | 72 | 0.667 | 0.750 | 1.026 | 4.333 |
| simplicity | 72 | 0.231 | 1.333 | 1.149 | 1.500 |
| path_linearity | 72 | 0.154 | 1.000 | 0.817 | 1.000 |
| reachability_density | 72 | 0.286 | 0.500 | 0.494 | 0.600 |
| density | 72 | 0.125 | 0.250 | 0.264 | 0.333 |

## Perplexity

| Property | Value |
|---|---|
| Training perplexity | 4.838 |
| Scored outcomes | 8,186 |
| Symbols | 7,525 |
| Traces | 661 |
| Alphabet size | 60 |
| Smoothing alpha | 0.100 |
| End-of-trace scored | yes |
| Probability source | `flexfringe_counts` |
| Unresolved events | 0 |
| Out-of-vocabulary events | 0 |
| Steps resolved via main model | 7,213 |
| Steps resolved via sinks model | 312 |

> PP = exp( -(1/N) * sum_i log P(outcome_i | state_i) ), N = total scored outcomes. Outcomes at a state are the alphabet symbols plus an explicit END event, so N counts one END per trace in addition to every symbol.

> P(sym|state)  = (trans_counts[sym] + alpha) / (N_state + alpha * n_outcomes) ; P(END|state)  = (total_final   + alpha) / (N_state + alpha * n_outcomes) ; N_state = total_paths + total_final ; n_outcomes = |alphabet| + 1

> Unresolved: uniform_over_outcomes: an unresolvable step (traverse state -1) is scored as 1/n_outcomes rather than skipped, and counted in unresolved_events

> Out-of-vocabulary: union_alphabet: n_outcomes spans the union of the training and scored alphabets plus END, so an unseen symbol receives alpha / (N_state + alpha * n_outcomes) rather than zero. Counted in oov_events.

## Output variance and determinism

**Exact-artifact match across 5 repeats**

| Artifact | Identical |
|---|---|
| Trace file (`.txt`) | yes |
| Main model JSON | yes |
| AG `.dot` (raw bytes) | 72 of 72 |
| AG `.dot` (tooltip-normalised) | 72 of 72 |

> **Verdict: fully deterministic**, byte-for-byte, across repeats.

| Metric | min | median | max | stdev |
|---|---:|---:|---:|---:|
| alert_throughput | 11,735.301 | 11,816.743 | 11,965.217 | 83.930 |
| dropped_bad_ip | 0 | 0 | 0 | 0.000 |
| dropped_category | 19,166 | 19,166 | 19,166 | 0.000 |
| dropped_non_alert | 48 | 48 | 48 | 0.000 |
| n_attack_graphs | 72 | 72 | 72 | 0.000 |
| n_dot_files | 72 | 72 | 72 | 0.000 |
| n_objectives | 8 | 8 | 8 | 0.000 |
| n_victims | 47 | 47 | 47 | 0.000 |
| parallel_edges | 62 | 62 | 62 | 0.000 |
| perplexity_training | 4.838 | 4.838 | 4.838 | 0.000 |
| raw_alerts | 1,033,067 | 1,033,067 | 1,033,067 | 0.000 |
| raw_records | 1,052,281 | 1,052,281 | 1,052,281 | 0.000 |
| self_loops | 32 | 32 | 32 | 0.000 |
| total_edges | 327 | 327 | 327 | 0.000 |
| total_nodes | 306 | 306 | 306 | 0.000 |
| unique_edges | 149 | 149 | 149 | 0.000 |
| unique_nodes | 121 | 121 | 121 | 0.000 |
| wall_clock_seconds | 87.945 | 89.050 | 89.668 | 0.628 |

## Metric definitions

Every formula actually used, verbatim from the code that computed it.

**`branching_factor`**

> edges_total / nodes  (paper definition; edge basis = multi-edges PRESERVED, self-loops included. NOTE: this is not the conventional mean out-degree)

**`density`**

> edges_simple_no_loops / (nodes * (nodes - 1))  (textbook directed simple-graph density, retained for comparability with the wider graph literature but NOT the headline density -- see reachability_density for why. Multi-edges COLLAPSED and self-loops EXCLUDED from the numerator, because V*(V-1) counts ordered distinct pairs and neither is representable in it; leaving them in can push density above 1. Null when nodes < 2.)

**`path_linearity`**

> longest_path_edges / edges_total  (longest path measured in EDGES traversed, over the same preserved edge basis)

**`reachability_density`**

> |{(u,v) : u != v, v reachable from u}| / (nodes * (nodes - 1))  (HEADLINE density. The paper gives no formula, defining density only by intent -- it "captures how easily an attacker can traverse the network". This is the literal reading: the fraction of ordered state pairs the attacker can actually get between, following edges any distance. Same normalisation as edge density, so it stays in [0,1] and remains comparable across graphs. Preferred over edge density because edge density is confounded by graph size -- measured across the 104 CPTC-2017 baseline AGs, corr(nodes, edge_density) = -0.79 versus corr(nodes, reachability_density) = +0.17 -- and because the paper already defines branching_factor = edges/nodes, which an edges-per-node density largely duplicates. Null when nodes < 2.)

**`simplicity`**

> nodes / edges_total  (reciprocal of branching_factor; same edge basis. Included only for comparability with Nadeem et al.)

**`post_dedup_alerts_per_ag`**

> post_dedup_alerts / n_attack_graphs

**`raw_alerts_per_ag`**

> raw_alerts / n_attack_graphs  (the same ratio over alerts SAGE actually ingests, i.e. after the event_type and dataset filters. Diverges sharply from the primary on CPTC-2018, where the bad-IP filter drops ~69% of records.)

**`raw_alerts_per_ag_node`**

> raw_alerts / total_ag_nodes  (nodes summed across graphs)

**`raw_alerts_per_unique_ag_node`**

> raw_alerts / unique_ag_nodes  (node union across graphs)

**`raw_records_per_ag`**

> raw_records / n_attack_graphs  (PRIMARY -- the paper defines compression as "number of raw alerts divided by number of generated attack graphs", and its own dataset counts pin "raw alerts" to every record in the file: it cites CCDC-2018 as 1,052,281, which is exactly the raw_records count here, whereas the post-filter alert count is 1,033,067. See RAW_ALERT_CONVENTION.)

**Edge bases**

- `edges_simple` -- distinct (tail, head) pairs, self-loops included
- `edges_simple_no_loops` -- distinct (tail, head) pairs where tail != head
- `edges_total` -- every edge line, multi-edges preserved, self-loops included

## Environment

| Property | Value |
|---|---|
| os | `Windows-11-10.0.26200-SP0` |
| processor | `AMD64 Family 25 Model 97 Stepping 2, AuthenticAMD` |
| cpu_count | `12` |
| total_ram_bytes | `33397133312` |
| python_version | `3.13.3` |
| graphviz_version | `dot - graphviz version 14.1.5 (20260411.2331)` |
| glibc_version | `ldd (Ubuntu GLIBC 2.39-0ubuntu8.7) 2.39` |
| wsl_kernel | `6.6.87.2-microsoft-standard-WSL2` |
| runs_flexfringe_via | `wsl -d Ubuntu` |
| flexfringe_sha256 | `69efbec90fb4140ec20b9fa450ef45bc709763cc6ba83bf8f2cbe32f5f4c5354` |
| flexfringe_ini_sha256 | `d20a6237768feaba9ce822fdf5ea1a783f6124c8cafb63ce641f8f191bc230b7` |
| iana_csv_sha256 | `757d5969a623680753269c420688fc01b050ce8dae9f47d90aab0a057f144dc8` |
| iana_pinned_at | `2026-08-20T23:49:10.083389+00:00` |
