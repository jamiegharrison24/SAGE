# Baseline metrics: `cptc-2017`

- **Schema version:** 1
- **Measured commit:** `20aa5ed99bfee77143d88ffdb19ed43a108810eb`
- **Recorded:** 2026-08-20T12:08:23.275033+00:00
- **Host:** `Rocinante`

## Reproduction

Run from the SAGE tree at the commit above, with `PYTHONHASHSEED=0`:

```bash
PYTHONHASHSEED=0 python sage.py D:\Projects\SAGE\SAGE\alerts\cptc-2017 cptc-2017-reference --dataset cptc --keep-files -t 1.0 -w 150
```

The IANA port-service CSV is fetched live by SAGE and changes AG structure when it changes upstream, so it is pinned for this baseline; see the digest in the environment block below and `evaluation/runner.py` for how the pinned copy is served.

## Headline metrics

| Metric | Value |
|---|---:|
| Raw records | 47,876 |
| Raw alerts (post-filter) | 47,876 |
| Post-dedup alerts | 43,299 |
| Attack graphs | 104 |
| Victims | 36 |
| Objectives | 25 |
| Total AG nodes | 1,885 |
| Unique AG nodes | 326 |
| Total AG edges | 3,024 |
| Compression (raw_records_per_ag) | 460.3 |
| Perplexity (training) | 13.478 |
| Perplexity (held-out) | 40.270 |
| Wall clock (s) | 97.5 |
| Throughput (records/s) | 491 |

## Per-graph structural distribution

| Metric | n | min | median | mean | max |
|---|---:|---:|---:|---:|---:|
| branching_factor | 104 | 0.667 | 1.356 | 1.503 | 4.000 |
| density | 104 | 0.032 | 0.076 | 0.094 | 0.333 |
| edges_total | 104 | 2 | 25.500 | 29.077 | 111 |
| longest_path_edges | 104 | 2 | 11.000 | 12.019 | 33 |
| nodes | 104 | 3 | 18.000 | 18.125 | 50 |
| path_linearity | 104 | 0.161 | 0.478 | 0.520 | 1.000 |
| reachability_density | 104 | 0.257 | 0.500 | 0.537 | 0.894 |
| simplicity | 104 | 0.250 | 0.738 | 0.747 | 1.500 |

## Perplexity

| Property | Value |
|---|---|
| Training perplexity | 13.478 |
| Scored outcomes | 6,234 |
| Symbols | 5,132 |
| Traces | 1,102 |
| Alphabet size | 135 |
| Smoothing alpha | 0.100 |
| End-of-trace scored | yes |
| Probability source | `flexfringe_counts` |
| Unresolved events | 0 |
| Out-of-vocabulary events | 0 |
| Steps resolved via main model | 3,164 |
| Steps resolved via sinks model | 1,968 |

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
| AG `.dot` (raw bytes) | 104 of 104 |
| AG `.dot` (tooltip-normalised) | 104 of 104 |

> **Verdict: fully deterministic**, byte-for-byte, across repeats.

| Metric | min | median | max | stdev |
|---|---:|---:|---:|---:|
| alert_throughput | 452.424 | 483.855 | 498.200 | 17.496 |
| dropped_bad_ip | 0 | 0 | 0 | 0.000 |
| dropped_category | 0 | 0 | 0 | 0.000 |
| dropped_non_alert | 0 | 0 | 0 | 0.000 |
| n_attack_graphs | 104 | 104 | 104 | 0.000 |
| n_dot_files | 104 | 104 | 104 | 0.000 |
| n_objectives | 25 | 25 | 25 | 0.000 |
| n_victims | 36 | 36 | 36 | 0.000 |
| parallel_edges | 618 | 618 | 618 | 0.000 |
| perplexity_training | 13.478 | 13.478 | 13.478 | 0.000 |
| raw_alerts | 47,876 | 47,876 | 47,876 | 0.000 |
| raw_records | 47,876 | 47,876 | 47,876 | 0.000 |
| self_loops | 21 | 21 | 21 | 0.000 |
| total_edges | 3,024 | 3,024 | 3,024 | 0.000 |
| total_nodes | 1,885 | 1,885 | 1,885 | 0.000 |
| unique_edges | 848 | 848 | 848 | 0.000 |
| unique_nodes | 326 | 326 | 326 | 0.000 |
| wall_clock_seconds | 96.098 | 98.947 | 105.821 | 3.736 |

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
| iana_pinned_at | `2026-08-20T12:08:18.813522+00:00` |

## Notes and caveats

- Held-out perplexity rests heavily on the unresolved-step policy: 33% of scored outcomes fell off the model entirely and took the uniform fallback. It is NOT a like-for-like comparison against the training figure.
- Repeat/exact-match section recomputed from stored cells after a fix to artifact filename keying; the run itself was not repeated.
