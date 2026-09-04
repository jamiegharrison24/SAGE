# Sigma corpus pull: extractor stress test + class-imbalance check

Two purposes, per `../STATUS.md`'s "what's not done" list:

1. First real-data test of `../hugging-face-suggestion/attack_mapper/
   extractors/sigma.py`, previously only exercised against one hand-written
   fixture.
2. Test `../tiered_approach/embedding_swap_findings.md`'s conclusion that
   Tier 2's weak accuracy is a training-corpus class-imbalance problem, not
   a feature-representation problem, and its specific recommendation:
   broaden coverage by folding in Sigma's ATT&CK-tagged rules.

## Fetching

```bash
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/SigmaHQ/sigma.git sigmahq
cd sigmahq && git sparse-checkout init --cone && git sparse-checkout set rules && git checkout
```

Sparse/shallow clone of just `rules/` (SigmaHQ's primary, best-maintained
rule tier — `rules-emerging-threats`/`rules-threat-hunting`/`rules-dfir`/
`rules-compliance` exist too and were not pulled). 3,144 `.yml` files, 18MB.
`sigmahq/` is gitignored-equivalent by convention here (not committed to
this repo — it's a third-party clone, reproducible from the command above)
but is left on disk for anyone continuing this locally.

## Extractor stress test result

`build_corpus.py` ran `SigmaExtractor` over all 3,144 rules:

- **100% parsed (3,144/3,144), 0 exceptions.** No `can_extract` misses, no
  extraction errors. `sigma_parse_failures.csv` is empty.
- 2,798 rules (89.0%) carry at least one `attack.tXXXX` tag and became a
  labeled-corpus row; the remaining 346 have tactic-only tags (e.g.
  `attack.execution` with no technique number) or no ATT&CK tags at all.

This is a stronger result than expected going in — real Sigma rules use
substantially more structure than the single fixture in
`../hugging-face-suggestion/tests/test_extractors.py` (nested selections,
list-of-dict selections, multiple named selection blocks, `1 of selection*`/
`all of` conditions) and none of it broke the extractor. Caveat: "parsed
without crashing" isn't the same as "extracted every field correctly" —
this run checked survival and technique-tag harvesting, not field-level
accuracy of every IoC extracted from arbitrarily complex `detection` blocks.

## Class-imbalance comparison: `sigma_labeled_corpus.csv` vs. `et_labeled_corpus.csv`

| | ET corpus | Sigma corpus | combined |
|---|---:|---:|---:|
| rows | 26,644 | 2,798 | 29,442 |
| distinct techniques | 45 | 390 | 397 |
| top-5-techniques share of rows | 81.3% | 22.8% | — |
| `T1203` (client-side browser exploit) training rows | 1 | 19 | 20 |

`embedding_swap_findings.md` singled out `T1203` by name as the case no
encoder could learn from a single training row. Sigma alone gives it 19.
More broadly: **352 techniques appear in the Sigma corpus that never appear
in the ET corpus at all** — this is exactly the "different domain
(host/EDR telemetry vs. network IDS), covers technique territory ET barely
touches" gap the recommendation predicted, not a marginal improvement.

Every one of the 6 ET techniques that had ≤1 training example on their own
has ≥2 examples once the two corpora are combined.

## Does it actually improve Tier 2's accuracy?

`../tiered_approach/tier2_classifier_combined.py` retrains Tier 2's exact
architecture (dual char/word TF-IDF + `OneVsRestClassifier(LinearSVC)`,
decision scores averaged) on the concatenated corpus and is scored against
the same hand-audited sample used everywhere else in this research branch
(`../tiered_approach/compare_combined_vs_audit.py`, identical convention to
`compare_tier2_vs_audit.py`). Full detail in
`../tiered_approach/tier2_combined_vs_audit_findings.md`.

**Yes, modestly — and the hub-collapse effect moves more than raw accuracy
does:**

| | ET-only corpus (existing baseline) | ET + Sigma combined |
|---|---:|---:|
| top-1 vs. hand-audit | 27/79 = 34.2% | **30/79 = 38.0%** |
| predicted `T1190` as top-1 (all 99 matched rows) | 76/99 = 76.8% | **52/99 = 52.5%** |

+3.8 points of top-1 accuracy is real but small — broadening the corpus is
not a silver bullet on its own. The bigger, more interpretable effect is on
hub-collapse: `embedding_swap_findings.md` and `../results.md` both flagged
every method's tendency to dump a large fraction of predictions onto a
handful of hub techniques (`T1190` above all). Giving the classifier 352
additional techniques' worth of real training examples visibly breaks that
habit — T1190's top-1 share drops by 24 points — even though the net
accuracy gain is modest, because a lot of what used to default to `T1190`
now defaults to some *other* wrong-but-different technique rather than a
correct one. 5-fold CV on the combined training corpus itself (not the hand-
audit sample) also drops from ~0.97-0.99 micro-F1 (ET-only) to ~0.91-0.93
(combined) — expected and not concerning on its own: a corpus with 397
sparsely-populated classes instead of 45 heavily-populated ones is a harder
in-distribution learning problem by construction, independent of whether it
generalizes better out-of-distribution (which the hand-audit number above is
what actually answers).

Still well short of the HF pipeline's 48.8% (`../hugging-face-suggestion/
findings.md`) — but that number draws on a different, non-overlapping lever
(SAGE's own `MicroAttackStage` bridge + vendor-declared tags, not a trained
classifier at all), so the two are not competing fixes for the same problem
and are worth combining rather than choosing between.

## Reproducing

```bash
# 1. fetch (see above)
# 2. build the labeled corpus + stress-test the extractor
python build_corpus.py                                   # -> sigma_labeled_corpus.csv, sigma_parse_failures.csv
# 3. retrain Tier 2 on ET+Sigma and score against the hand-audited sample
python ../tiered_approach/tier2_classifier_combined.py
python ../tiered_approach/compare_combined_vs_audit.py
```
