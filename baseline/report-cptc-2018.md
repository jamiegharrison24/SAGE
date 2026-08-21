# Baseline metrics: `cptc-2018`

- **Schema version:** 1
- **Measured commit:** `20aa5ed99bfee77143d88ffdb19ed43a108810eb`
- **Recorded:** 2026-08-20T21:56:37.408286+00:00
- **Host:** `Rocinante`

## Reproduction

Run from the SAGE tree at the commit above, with `PYTHONHASHSEED=0`:

```bash
PYTHONHASHSEED=0 python sage.py D:\Projects\SAGE\SAGE\alerts\cptc-2018 cptc-2018-reference --dataset cptc --keep-files -t 2.0 -w 200
```

The IANA port-service CSV is fetched live by SAGE and changes AG structure when it changes upstream, so it is pinned for this baseline; see the digest in the environment block below and `evaluation/runner.py` for how the pinned copy is served.

## Headline metrics

| Metric | Value |
|---|---:|
| Raw records | 331,554 |
| Raw alerts (post-filter) | 101,571 |
| Post-dedup alerts | 71,096 |
| Attack graphs | 75 |
| Victims | 12 |
| Objectives | 34 |
| Total AG nodes | 1,283 |
| Unique AG nodes | 242 |
| Total AG edges | 2,641 |
| Compression (raw_records_per_ag) | 4,420.7 |
| Perplexity (training) | 9.419 |
| Perplexity (held-out) | 35.897 |
| Wall clock (s) | 85.2 |
| Throughput (records/s) | 3,890 |

## Per-graph structural distribution

| Metric | n | min | median | mean | max |
|---|---:|---:|---:|---:|---:|
| nodes | 75 | 3 | 17 | 17.107 | 34 |
| edges_total | 75 | 2 | 29 | 35.213 | 136 |
| longest_path_edges | 75 | 2 | 13 | 13.027 | 26 |
| branching_factor | 75 | 0.667 | 1.783 | 1.978 | 8.500 |
| simplicity | 75 | 0.118 | 0.561 | 0.669 | 1.500 |
| path_linearity | 75 | 0.110 | 0.414 | 0.534 | 1.000 |
| reachability_density | 75 | 0.295 | 0.500 | 0.535 | 0.865 |
| density | 75 | 0.037 | 0.079 | 0.093 | 0.333 |

## Perplexity

| Property | Value |
|---|---|
| Training perplexity | 9.419 |
| Scored outcomes | 4,149 |
| Symbols | 3,516 |
| Traces | 633 |
| Alphabet size | 142 |
| Smoothing alpha | 0.100 |
| End-of-trace scored | yes |
| Probability source | `flexfringe_counts` |
| Unresolved events | 0 |
| Out-of-vocabulary events | 0 |
| Steps resolved via main model | 1,974 |
| Steps resolved via sinks model | 1,542 |

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
| AG `.dot` (raw bytes) | 75 of 75 |
| AG `.dot` (tooltip-normalised) | 75 of 75 |

> **Verdict: fully deterministic**, byte-for-byte, across repeats.

| Metric | min | median | max | stdev |
|---|---:|---:|---:|---:|
| alert_throughput | 3,966.621 | 4,065.653 | 4,096.395 | 50.770 |
| dropped_bad_ip | 228,608 | 228,608 | 228,608 | 0.000 |
| dropped_category | 1,375 | 1,375 | 1,375 | 0.000 |
| dropped_non_alert | 0 | 0 | 0 | 0.000 |
| n_attack_graphs | 75 | 75 | 75 | 0.000 |
| n_dot_files | 75 | 75 | 75 | 0.000 |
| n_objectives | 34 | 34 | 34 | 0.000 |
| n_victims | 12 | 12 | 12 | 0.000 |
| parallel_edges | 971 | 971 | 971 | 0.000 |
| perplexity_training | 9.419 | 9.419 | 9.419 | 0.000 |
| raw_alerts | 101,571 | 101,571 | 101,571 | 0.000 |
| raw_records | 331,554 | 331,554 | 331,554 | 0.000 |
| self_loops | 15 | 15 | 15 | 0.000 |
| total_edges | 2,641 | 2,641 | 2,641 | 0.000 |
| total_nodes | 1,283 | 1,283 | 1,283 | 0.000 |
| unique_edges | 449 | 449 | 449 | 0.000 |
| unique_nodes | 242 | 242 | 242 | 0.000 |
| wall_clock_seconds | 80.938 | 81.550 | 83.586 | 1.037 |

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
| iana_pinned_at | `2026-08-20T21:55:05.211183+00:00` |

## Notes and caveats

- Held-out perplexity rests heavily on the unresolved-step policy: 39% of scored outcomes fell off the model entirely and took the uniform fallback. It is NOT a like-for-like comparison against the training figure.
