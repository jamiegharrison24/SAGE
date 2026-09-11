# Elastic detection-rules corpus: technique-diversity lever

Follow-on to `../../STATUS.md` effort 11's "highest-leverage remaining work"
note: `tier2_combined` and `knn_corpus` together answer 350 of 397 scoreable
rows, and both draw on the same labeled corpus. That corpus is ET-dominated
— 26,644 of its 29,933 rows cover only 45 distinct techniques — which is the
mechanism behind the T1190 hub collapse (predicted on 33.5% of rows against a
28.5% true base rate; micro 38.8% vs macro 21.1%).

The hypothesis under test: adding a *narrow but diverse* corpus should move
macro accuracy and calibration without necessarily moving micro, because it
addresses class coverage rather than adding more rows in the classes that are
already saturated.

## Fetching

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules
```

Shallow/sparse clone, 2,101 `.toml` files. `detection-rules/` is gitignored
(see repo `.gitignore`) — third-party, reproducible from the command above.

## Schema

Elastic rules are TOML. Title is `rule.name`; ATT&CK mappings live in repeated
`[[rule.threat]]` blocks, each containing `[[rule.threat.technique]]` entries
with an `id`, an optional nested `[[rule.threat.technique.subtechnique]]` list,
and one `[rule.threat.tactic]` table.

**Granularity decision — this corpus differs from Sigma/Splunk deliberately.**
Sigma and Splunk tag one ID per entry at the author's chosen granularity, so
their builders emit exactly that. Elastic instead nests the sub-technique
*inside* its parent, asserting both, so `build_corpus.py` emits both. This is
faithful-to-source in each case rather than a uniform rule. It also happens to
suit the evaluation set, which is predominantly parent-level (T1190, T1046,
T1018) — emitting sub-techniques alone would produce labels that can never
match parent-level ground truth. Deriving parents from sub-techniques across
*all* corpora is a separate experiment, not mixed into this one, since it would
shift the class-prior and IDF denominators everywhere at once.

`rules/_deprecated/` (130 files) and any rule with `metadata.maturity =
"deprecated"` are skipped — retired detections whose mappings aren't maintained.

## Build result

- **1,971 files parsed, 100%, 0 exceptions** (after the deprecated-dir skip).
- 79 parsed rules carry no ATT&CK technique at all and are dropped.
- **1,892 labeled rows**, `../data/elastic_labeled_corpus.csv`.

Diversity versus the existing corpora — the reason this one was pulled:

| corpus  | rows   | distinct techniques | top-5 share |
|---------|-------:|--------------------:|------------:|
| ET      | 26,644 |                  45 |       81.3% |
| Sigma   |  3,289 |                 398 |       23.7% |
| Elastic |  1,892 |                 444 |       15.3% |

Elastic adds 6.3% more rows but the most technique coverage of any corpus in
the project, and the flattest distribution.

## Measured effect

`validate.py` against the 500-row labeled set (397 scoreable), LLM off. The
baseline was re-run on unchanged code first and reproduced effort 11's numbers
exactly (154/397, 21.1% macro, T1190 33.5%), confirming the delta below is
attributable to the corpus and not to environment drift.

| metric | baseline (ET+Sigma) | +Elastic | delta |
|---|---:|---:|---:|
| micro top-1 | 38.8% (154/397) | 38.8% (154/397) | 0.0 |
| **macro** | 21.1% | **22.2%** | **+1.1** |
| T1190 share (true base rate 28.5%) | 33.5% | **29.0%** | **-4.5** |

Predicted before running, and confirmed on all three: macro up, hub share down
toward the true base rate, micro flat. The corpus fixes class *coverage*, which
is a calibration problem, not a top-line accuracy problem — so this is the
shape of result to expect, and reporting it as a headline accuracy win would be
overstating it.

## The check that separates signal from artifact

Adding rows changes `knn_resolver.py`'s IDF denominator for *every* technique,
so macro and hub share can move even on rows where no Elastic neighbour is ever
retrieved. `knn_resolver` therefore now tracks which corpus each retrieved
neighbour came from (`neighbour_source_counts`), and `validate.py` reports
top-1 accuracy split by the corpus that supplied the winning neighbour:

```
kNN retrieval pool by corpus: {'et': 1460, 'sigma': 722, 'elastic': 398}
knn_corpus top-1 accuracy by winning corpus:
    elastic 12/43 = 27.9%,  et 19/77 = 24.7%,  sigma 17/56 = 30.4%
```

Elastic rows are genuinely retrieved — 398 of 2,580 neighbours (15.4%) — and
win 43 top-1 rows at an accuracy comparable to Sigma and better than ET. So the
gain is new signal, not a reweighting artifact. This distinction is why the
check exists: effort 8's headline "win" was exactly such an artifact.

A second-order effect worth noting: the source breakdown shifted from
`{knn_corpus: 290, tier2_combined: 161}` to `{knn_corpus: 258,
tier2_combined: 193}`. The broader corpus gives the classifier more classes it
will vote positive on, so 32 rows moved up from the weaker retrieval layer to
the stronger classifier layer (45.2% vs 27.9% accuracy on the baseline run).

## Caveat

Elastic's rules are host/cloud/EDR telemetry ("FortiGate Configuration File
Downloaded"); the evaluation set is network IDS signatures ("ET SCAN Potential
VNC Scan 5800-5820"). The register gap is real and caps how much this corpus
can contribute — 27.9% accuracy on the rows it wins is not high in absolute
terms. It helps because it covers techniques nothing else covered, not because
it matches the evaluation domain.
