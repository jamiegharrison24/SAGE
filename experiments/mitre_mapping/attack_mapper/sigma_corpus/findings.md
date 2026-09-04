# Sigma corpus pull: extractor stress test + class-imbalance check

Two purposes, per `../../STATUS.md`'s "what's not done" list:

1. First real-data test of `../extractors/sigma.py`, previously only
   exercised against one hand-written fixture.
2. Test `../../archive/tiered_approach/embedding_swap_findings.md`'s conclusion that
   Tier 2's weak accuracy is a training-corpus class-imbalance problem, not
   a feature-representation problem, and its specific recommendation:
   broaden coverage by folding in Sigma's ATT&CK-tagged rules.

## Fetching

```bash
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/SigmaHQ/sigma.git sigmahq
cd sigmahq && git sparse-checkout init --cone
git sparse-checkout set rules rules-threat-hunting rules-dfir rules-emerging-threats
git checkout
```

Sparse/shallow clone. Started with just `rules/` (SigmaHQ's primary,
best-maintained tier, 3,144 files), then extended to
`rules-threat-hunting/` (140 files) and `rules-emerging-threats/` (473
files, year-organized campaign/CVE-specific rules — largely non-overlapping
with our own ET Suricata corpus despite similar subject matter, since
Sigma's authors and tagging are independent of ET's). `rules-dfir/` is in
the sparse-checkout but currently has 0 `.yml` files at the paths pulled.
`rules-compliance/` (compliance-framework rules, not attacker-technique
rules) was deliberately not pulled. 3,757 `.yml` files total, ~21MB.
`sigmahq/` is gitignored-equivalent by convention here (not committed to
this repo — it's a third-party clone, reproducible from the command above)
but is left on disk for anyone continuing this locally.

## Extractor stress test result

`build_corpus.py` ran `SigmaExtractor` over all 3,757 rules (initially just
the 3,144 in `rules/`, then re-run after extending the sparse-checkout):

- **100% parsed (3,757/3,757), 0 exceptions**, on both the original 3,144-file
  pull and the extended 3,757-file one. No `can_extract` misses, no
  extraction errors. `sigma_parse_failures.csv` is empty.
- 3,289 rules (87.6%) carry at least one `attack.tXXXX` tag and became a
  labeled-corpus row; the remaining 468 have tactic-only tags (e.g.
  `attack.execution` with no technique number) or no ATT&CK tags at all.

This is a stronger result than expected going in — real Sigma rules use
substantially more structure than the single fixture in
`../../tests/test_extractors.py` (nested selections,
list-of-dict selections, multiple named selection blocks, `1 of selection*`/
`all of` conditions) and none of it broke the extractor. Caveat: "parsed
without crashing" isn't the same as "extracted every field correctly" —
this run checked survival and technique-tag harvesting, not field-level
accuracy of every IoC extracted from arbitrarily complex `detection` blocks.

## Class-imbalance comparison: `sigma_labeled_corpus.csv` vs. `et_labeled_corpus.csv`

| | ET corpus | Sigma corpus | combined |
|---|---:|---:|---:|
| rows | 26,644 | 3,289 | 29,933 |
| distinct techniques | 45 | 398 | 405 |
| top-5-techniques share of rows | 81.3% | 23.7% | — |
| `T1203` (client-side browser exploit) training rows | 1 | 35 | 36 |

`embedding_swap_findings.md` singled out `T1203` by name as the case no
encoder could learn from a single training row. Sigma alone gives it 35 now
(19 with just `rules/`; the `rules-emerging-threats`/`rules-threat-hunting`
extension added 16 more). More broadly: **360 techniques appear in the
Sigma corpus that never appear in the ET corpus at all** — this is exactly
the "different domain (host/EDR telemetry vs. network IDS), covers
technique territory ET barely touches" gap the recommendation predicted,
not a marginal improvement.

Every one of the 6 ET techniques that had ≤1 training example on their own
has ≥4 examples once the two corpora are combined (`T1498` the smallest
gain at 4, `T1203` the largest at 36).

## Does it actually improve Tier 2's accuracy?

`../../archive/tiered_approach/tier2_classifier_combined.py` retrains Tier 2's exact
architecture (dual char/word TF-IDF + `OneVsRestClassifier(LinearSVC)`,
decision scores averaged) on the concatenated corpus and is scored against
the same hand-audited sample used everywhere else in this research branch
(`../../archive/tiered_approach/compare_combined_vs_audit.py`, identical convention to
`compare_tier2_vs_audit.py`). Full detail in
`../../archive/tiered_approach/tier2_combined_vs_audit_findings.md`.

**Yes, modestly — and the hub-collapse effect moves more than raw accuracy
does:**

| | ET-only corpus (existing baseline) | ET + Sigma combined |
|---|---:|---:|
| top-1 vs. hand-audit | 27/79 = 34.2% | **30/79 = 38.0%** |
| predicted `T1190` as top-1 (all 99 matched rows) | 76/99 = 76.8% | **52/99 = 52.5%** |

+3.8 points of top-1 accuracy is real but small — broadening the corpus is
not a silver bullet on its own. The bigger, more interpretable effect is on
hub-collapse: `embedding_swap_findings.md` and `../../archive/results.md` both flagged
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

Still well short of the main pipeline's 48.8% (`../../findings.md`) — but
that number draws on a different, non-overlapping lever (SAGE's own
`MicroAttackStage` bridge + vendor-declared tags, not a trained classifier
at all), so the two aren't competing fixes for the same problem. Update:
they've since been combined -- `../classifier_resolver.py` stacks this
ET+Sigma classifier into the main pipeline as a candidate source, taking the
result to 53.8%. See `../../findings.md`'s "Update" section.

## Update: extended pull (rules-threat-hunting + rules-emerging-threats) — no change on this sample

The numbers above are from the original `rules/`-only pull (2,798 labeled
rows). Extending the sparse-checkout added `rules-threat-hunting/` and
`rules-emerging-threats/`, taking the corpus to 3,289 rows / 398 distinct
techniques (`T1203` alone: 19 -> 35 examples) — a real, measurable
broadening (see the table above, now updated to reflect the extended pull).

Re-ran `validate.py` against the live pipeline (which retrains
`classifier_resolver.py` from the current `data/*_labeled_corpus.csv` files
at construction time — not a stale artifact): **identical 53.8% (43/80),
identical source breakdown** (`tier2_combined` still resolves exactly 6
rows, same accuracy). None of the additional 491 rows / 8 techniques
happened to be exactly what was needed for the small number of rows in
*this* 80-row sample that reach the classifier at all (only 18 rows ever
get a turn, per `../../findings.md`'s "Update" section on stacking) — the
broadened corpus is real and should help on a larger or different sample,
but this specific sample doesn't move. Worth knowing before assuming every
corpus-broadening pull pays off immediately: the effect is gated by how
many rows actually reach that candidate source, which here is a small,
specific subset.

## Reproducing

```bash
# 1. fetch (see above)
# 2. build the labeled corpus + stress-test the extractor
python build_corpus.py                     # -> ../data/sigma_labeled_corpus.csv, ../data/sigma_parse_failures.csv
# 3. the active pipeline picks the new corpus up automatically -- classifier_resolver.py
#    reads ../data/*_labeled_corpus.csv at construction time, no extra step needed
python ../../validate.py

# historical: retrain the ORIGINAL (archived) Tier 2 architecture on ET+Sigma and score it
# separately, the standalone comparison this findings.md's numbers above come from
python ../../archive/tiered_approach/tier2_classifier_combined.py
python ../../archive/tiered_approach/compare_combined_vs_audit.py
```
