# MITRE ATT&CK mapping research — status

Branch `research/b2-mitre-eval`. Standalone research spike under
`experiments/mitre_mapping/` — does not touch the production pipeline (see
repo `CLAUDE.md`). Goal: find a way to map SAGE's Suricata/ET signature
vocabulary to MITRE ATT&CK technique IDs that beats the current mapping
quality, and ideally generalizes beyond Suricata.

**The active approach is `attack_mapper/`** (the HF-suggested generalisable
pipeline, effort 3 below, now stacked with effort 4 — see effort 5). Effort
1 (the original 7-method comparison) and effort 2 (`tiered_approach`) are
superseded and live under `archive/` — kept for the record (real completed
research, cited by later efforts' findings), not because anything there is
still being iterated on. See "Where things live" for the directory map.

Twelve sub-experiments have run so far, in order. Each has its own detailed
write-up; this file is the index and the current bottom line.

**Planned next, not started:** entity-aware normalisation —
`entity_normalisation_plan.md` is the source of truth for that work (design,
settled decisions, known traps, sequencing and the prediction to judge it
against). It is gated on the `reviewer_verdict` scoring decision in "What's not
done" below, and will become effort 13 here once measured.

## 1. Seven-method zero-shot/kNN/SMET comparison — `archive/results.md`, `archive/SMET_STATUS.md`

First spike. Built a 773-signature ground truth by propagating
`signatures/alert_signatures.py`'s `MicroAttackStage` labels through a
34-row bridge table (`archive/bridge_table_validated.json`, validated with 0
problems against live STIX). Compared 7 methods against it:

| method | top-1 (scoreable) |
|---|---:|
| zero-shot embedding similarity, full technique list (ATTACK-BERT/MiniLM, 4 variants) | 5.5-8.4% |
| kNN (k=5) over the 773 labeled signatures | 56.6-61.0% *(inflated — see caveat below)* |
| SMET (external pretrained classifier, unblocked via a user-space Miniconda Python 3.9 env — see `archive/SMET_STATUS.md`) | 13.2% |

**Caveat that matters:** the kNN numbers are not solving the same problem
as the rest. Because ground truth is *propagated from* `MicroAttackStage`,
kNN over the same 773 hand-labeled signatures mostly just re-derives the
original stage clustering wearing a technique-ID costume — it's not
evidence technique-level classification is "mostly solved." SMET is the
strongest genuinely-comparable zero-shot number, and it's still weak.
Legacy: SMET itself (the external repo + its own Python 3.9 conda env) is
not present on this machine anymore, only `archive/SMET_STATUS.md`'s
write-up — nothing to clean up there.

## 2. Tiered approach (Tier 0-4) — `archive/tiered_approach/strategy.md`, `tier2_vs_audit_findings.md`, `embedding_swap_findings.md`

Tier 0 (harvest vendor-declared MITRE tags) + Tier 1 (STIX malware/tool
alias table, high precision/narrow recall) + Tier 2 (supervised classifier
trained on a 26,644-row ET-labeled corpus) + Tier 3 (similarity fallback) +
Tier 4 (abstain to human review).

**Best number: Tier 2 TF-IDF classifier, 34.2% top-1 (27/79)** against a
100-row hand-audited sample (`hand_audit_sample*.csv`, 3 batches).

`embedding_swap_findings.md`: swapping Tier 2's TF-IDF features for MiniLM
or ATTACK-BERT embeddings does **not** help (29.1% / 30.4% top-1, both
worse). Root cause identified: severe class imbalance in the training
corpus — top 5 techniques are 81.3% of rows, and `T1203` (client-side
browser exploitation) has exactly **1** training example — not a feature-
representation problem, so no encoder swap fixes it.

## 3. Generalisable HF-suggested pipeline — `findings.md`

Implements the extract -> enrich -> narrate -> embed -> LLM-reason
architecture from a Hugging-Face-chat suggestion (`plan.md`,
`generalisable mitre mapper.md`), scoped to what this repo can actually
exercise: Suricata (primary, since SAGE ingests Suricata) + Sigma
extractors, an IoC resolver reusing Tier 1's alias table plus SAGE's own
`MicroAttackStage` bridge table, a MiniLM embedding fallback, and a
swappable-but-unconfigured LLM layer.

**Best number: 48.8% top-1 (39/80)** against the same hand-audited sample —
beats Tier 2. **But** the gain is almost entirely two SAGE/vendor-internal
signals, not the "generalisable" architecture itself:

| source | precision | rows |
|---|---:|---:|
| ET's own declared `mitre_technique_id` metadata (Tier 0) | 81.8% | 11 |
| SAGE's `MicroAttackStage` -> bridge table | 50.0% | 60 |
| MiniLM embedding similarity (Layer A) | 0.0% | 8 |
| STIX tool/malware alias match (Layer C) | 0.0% | 1 |

The LLM reasoning layer never executed — no `openai`/`anthropic` package, no
API key, no `.env` anywhere in this environment. Also flagged in
`findings.md`: the hand-audited sample's `current_gt` column is itself
derived via that same bridge table, so part of the bridge_table row's 50%
reflects "does the stage-level judgment still hold up under independent
review," not fully independent inference.

## 4. Sigma corpus pull — `attack_mapper/sigma_corpus/findings.md`

Follow-on to effort 3's recommendation. Sparse/shallow-cloned SigmaHQ,
starting with just `rules/` (3,144 files) and later extended to include
`rules-threat-hunting/` and `rules-emerging-threats/` (3,757 files total,
~21MB), and ran it through `SigmaExtractor` for the first time against real
(non-fixture) data — **100% parsed, 0 exceptions**, on both pulls.
3,289 rules yielded a labeled (rule -> ATT&CK technique) corpus,
`sigma_labeled_corpus.csv`, built the same way as the tiered-approach's
`et_labeled_corpus.csv` so the two are directly comparable:

| | ET corpus | Sigma corpus |
|---|---:|---:|
| rows | 26,644 | 3,289 |
| distinct techniques | 45 | 398 |
| top-5-techniques share | 81.3% | 23.7% |
| `T1203` training rows | 1 | 35 |

Confirms `embedding_swap_findings.md`'s prediction directly: Sigma covers
360 techniques the ET corpus never tags at all, and every ET technique that
had ≤1 training example gets ≥4 once combined. Re-running `validate.py`
against the live pipeline after the extended pull produced an **identical**
53.8%/same source breakdown, though — the extra rows didn't happen to touch
the small number of hand-audit rows that reach the classifier at all. See
`attack_mapper/sigma_corpus/findings.md`'s "Update" section.

Retrained Tier 2's exact classifier architecture on the concatenated
ET+Sigma corpus (`archive/tiered_approach/tier2_classifier_combined.py`,
scoring the original archived Tier 2 in isolation — a separate check from
effort 5 below) and scored it the same way: **38.0% top-1 (30/79)**, vs.
34.2% (27/79) ET-only — a real but modest +3.8-point gain. The bigger effect
is on hub-collapse, not raw accuracy: top-1 `T1190` predictions drop from
76.8% to 52.5% of all matched rows. Broadening the corpus is a genuine,
evidence-backed lever, just not individually a large one — see
`attack_mapper/sigma_corpus/findings.md` for the full breakdown, including
why this and effort 3's 48.8% are non-competing levers (different signal
sources), which effort 5 stacks together.

## 5. Stacking effort 3 + effort 4 — `findings.md` ("Update" section)

The untried combination flagged above: `attack_mapper/classifier_resolver.py`
wires a live-trained ET+Sigma classifier into the pipeline as a new
candidate source, slotted between the high-precision IoC/bridge sources and
the low-precision embedding fallback. It only ever gets a turn on rows where
`declared`/`ioc_alias`/`bridge_table` found nothing (18 of 80 scoreable
rows, pre-stacking) — i.e. exactly the rows that used to fall through to the
near-useless embedding layer.

**Result: 53.8% top-1 (43/80), up from 48.8%.** The classifier claims 5 of
those 18 rows (only when its own prediction clears a positive decision-
function score) and gets 4 right — 80% precision, though on a small enough
sample (5 rows) that this is suggestive, not a stable estimate. The other 13
still fall through to embedding, still at ~0% precision. Because the two
levers fire on disjoint rows by construction, the gain is strictly additive
— resolving the "do they add or overlap" open question from effort 4: they
add.

**Also effort 5:** the whole package was promoted from
`hugging-face-suggestion/` (a subfolder alongside `tiered_approach/`) to
`experiments/mitre_mapping/attack_mapper/` directly, and made fully
self-contained — no imports reach outside its own tree anymore (previously
it reached into `tiered_approach/` for the alias table, `normalize.py`, the
training corpora, and the vendored ET ruleset). `tiered_approach/` and
effort 1's top-level files moved to `archive/`, unmodified internally, per
the user's direction that this is the approach going forward, not one of
several being compared. Re-ran `validate.py` after the move: identical
53.8%, confirming the restructure changed only file locations. See
`findings.md`'s "Update: package promoted and made self-contained" section
and "Where things live" below for the full picture.

## 6. LLM layer (Layer D) tested — `findings.md` ("Update: LLM layer tested" section)

First time Layer D has actually executed anywhere in this branch. Set up a
local Ollama server (free, no repo footprint — `attack_mapper/LLM_SETUP.md`)
and ran `validate.py --llm ollama`. `llama3.1:8b` repeatedly triggered
Windows OOM kills on this 16GB machine (also surfaced and fixed a real
memory bug: `classifier_training.py` was spawning one parallel training
worker per CPU core via `n_jobs=-1`, multiplying memory several-fold — now
capped at 4). `llama3.2:3b` (2GB) completed cleanly.

**Result: 33.8% top-1 (27/80), down from 53.8% — a 20-point regression.**
Every row got reprocessed by the LLM (source breakdown: `{'llm': 100}`),
including ones `declared`/`bridge_table` had already answered at
81.8%/50% precision — `reasoner.py`'s current design only skips Layer D
when the candidate pool is empty, which with the embedding fallback in
place is never. `T1190` hub-collapse rose from 16% to 30% of top-1
predictions, and self-reported confidence carries no signal about
correctness (0.80 average on wrong answers, 0.83 on right ones). Read as
evidence against *this* combination (a 3B local model, full-override
design) specifically, not against LLM-assisted mapping as a concept — the
stronger `llama3.1:8b` was never actually scored (memory-killed before
finishing), so model capability and reasoner design are still confounded.
`AttackMapperPipeline()`'s default is unaffected (`NullLLMClient`); this
result lives in a separate `validation_report_llm.md`, not the committed
baseline.

## 7. Gating fix + `llama3.1:8b` on a bigger machine — `findings.md`

Follow-on to effort 6, on a second machine (31GB RAM, no OOM risk).
Implemented both untried fixes from effort 6: `reasoner.py`'s Layer D now
only fires when the prior top candidate's confidence is below
`Settings.llm_gate_confidence` (0.5), and blends confidence rather than
fully overriding it. Then ran `llama3.1:8b` (never actually scored before —
it OOM-killed on the 16GB machine).

**Result: 46.2% top-1 (37/80), down from 53.8% — an 8-point regression, vs.
effort 6's 20-point regression.** The gating/blending fix works as intended
(33/100 rows never reach the LLM at all; blended rows often keep the
correct prior answer), but a third failure mode shows up once the first two
are fixed: the LLM sometimes proposes a technique **outside the candidate
list it was shown**, at high self-reported confidence (0.80-0.95), and that
free-floating guess wins the top-1 sort against a correct-but-low-confidence
prior — 9 of 43 miss rows follow this exact pattern (e.g. correct `T1190`
web-exploit rows overridden to `T1059`). This separates the two variables
effort 6 left confounded: a stronger model with the design bugs fixed still
regresses, just less badly, for a reason neither fix touches. See
`findings.md`'s new "Update: gating fix + llama3.1:8b" section for the full
breakdown and the suggested next step (reject/down-weight off-list
technique IDs from the LLM response).

## 8. `qwen2.5:7b-instruct` — a headline number that doesn't survive inspection — `findings.md`

Tried a third model (4.7GB, reportedly stronger JSON/instruction-following
than Llama at this size), same gated+blended reasoner as effort 7. Raw
result looked like the branch's first genuine LLM win: **62.5% top-1
(50/80), up from 53.8% off.** It isn't one: 47 of the 48 free-floating LLM
answers are `T1190` at a flat 0.90 confidence, regardless of the rule —
the model collapsed to guessing the single most common technique (35% of
this sample's true labels) almost unconditionally. Precision on those 47
`T1190` guesses is only 46.8%, not the 0.90 self-reported for every one.
This is the same hub-collapse failure every non-LLM method in this branch
has fought, now severe enough to look like a win purely because this
80-row sample happens to be 35% `T1190`. **Would very likely hurt on a
differently-balanced corpus** (e.g. what `sage.py` actually ingests).

**None of the 3 models / 2 reasoner designs tried so far survive scrutiny.**
`llama3.1:8b` fails by answering off-list; `qwen2.5:7b-instruct` fails by
collapsing to the modal class — the off-list-rejection fix (effort 7)
wouldn't catch the latter, since `T1190` is a legitimate in-list candidate
for most of these rows. See `findings.md`'s new "Update: qwen2.5:7b-instruct"
section for the full breakdown and an untried fix direction (penalize
low-specificity/repeated-technique reasoning, not just off-list IDs).

## 9. 500-row blind-labeled set — the 53.8% doesn't survive it — `findings.md`

Grew the evaluation set from 100 to 500 rows (400 new, `model_proposed`, in
`attack_mapper/data/labeled_set_v2.csv`), labeled **blind to
`micro_attack_stage` and `current_gt`** — the signals the pipeline's dominant
`bridge_table` source keys off, and the same ones the original 100 rows'
ground truth was derived through.

**Result: 34.1% top-1 (108/317) on the blind rows, vs 53.8% (43/80) on the
original 100.** 34.1% is indistinguishable from the ET-only Tier 2 classifier's
34.2% — on a sample not scored against a rewritten copy of the bridge table,
this pipeline does not clearly beat the classifier it was built to improve on.

All three competing explanations were measured, not argued:
- **Labeling drift** — ruled out. An independent re-label of 25 rows (fresh
  agent, no memory of pass 1) agrees 88% exactly / 96% on technique overlap,
  and all 3 disagreements are one convention gap (`ET POLICY` executable
  downloads). See `label_queue/CONSISTENCY.md`.
- **Circularity in the original set** — confirmed and quantified: labels agree
  with the bridge table's own answer 42.7% when labeled with the stage visible,
  **28.8%** when blind.
- **Harder sample** — 52 distinct true labels vs 19.

**The bigger finding is macro-average: 18.6% across 52 techniques**, vs 38.0%
micro. The pipeline resolves a few common techniques and largely fails on the
long tail — the same class-imbalance pathology already known in the *training*
corpus, now shown to have been in the *evaluation* set too, which is why no
prior number in this branch revealed it. `validate.py` now reports macro on
every run; retroactively, it would have caught effort 8's fake 62.5% win
automatically.

**Per-source accuracy at real scale reframes where the loss comes from.**
`bridge_table` fires on 276/397 scoreable rows (70% of volume) at only 34.8%
accuracy — it is both the largest bucket and the weakest of the three
high-volume sources. `declared` (71.8%, 39 rows) and the classifier (**66.7%,
36 rows** — a real number now, not the 5-row sample effort 5 flagged as
unstable) both hold up well. The bottleneck is structural: `bridge_table` maps
~12 broad `MicroAttackStage` values onto 52+ specific techniques in this
sample, which caps its ceiling regardless of implementation quality. The
highest-leverage future lever is improving or replacing `bridge_table`'s
coverage, not the classifier/embedding/LLM layers, none of which touch more
than 38 rows each.

Also fixed a reproducibility footgun: `emerging-all.rules` is gitignored, so a
fresh clone silently scored **43.8%** instead of 53.8% (`declared` drops 11
rows → 0). `validate.py` now hard-fails with the fetch command. And surfaced
two missing commas in `signatures/alert_signatures.py` (lines 671, 821) that
fuse four real signatures into two unmatched strings — production code,
unfixed, see `findings.md`.

## 10. `bridge_table` removed — 32.7%, the new honest floor — `findings.md`

Effort 9 found `bridge_table`'s weakness was structural, not tunable
(~12 broad `MicroAttackStage` values onto 52+ specific techniques). Per the
user's explicit direction, it is now **removed from the pipeline entirely** —
no `micro_attack_stage` field, no bridge-table lookup, anywhere in
`attack_mapper/`.

**Result: 32.7% top-1 (130/397), down from 38.0%; macro-average 13.5%, down
from 18.6%.** This is an expected, accepted regression, not a bug: the 276
rows `bridge_table` used to answer (at 34.8% accuracy) now mostly fall to
`embedding`, which collapses to 4.5% on them, tripling `T1190`'s predicted
share to 38.5% — the same majority-class-collapse pattern the LLM layer
showed in efforts 6-8. `declared` (71.8%) and `ioc_alias` (37.5%) are
unaffected. `tier2_combined` now carries 218/397 scoreable rows at 42.7%,
the largest remaining pool.

**32.7% is the new baseline to build up from.** Its point is not that it's
higher — it's lower — but that nothing in it is capped by a structurally
lossy coarse-to-fine lookup. The highest-leverage next step is a genuine
`bridge_table` replacement or a stronger classifier, not embedding tuning
(never exceeded single digits at any point in this branch).

## 11. kNN over the labeled corpus + prior correction — 38.8% / 21.1% — `findings.md`

Rebuilt the fallback layers after effort 10 removed `bridge_table`. **Best
macro-average this project has measured, without `bridge_table`.**

- **`knn_resolver.py` replaces `embedder.py`** (deleted). The old layer
  compared rule text to MITRE *description prose* — a register mismatch that
  measured 4.5% top-1. The new one retrieves against the ~30k labeled ET+Sigma
  corpus (rule text vs rule text), with IDF-weighted voting to avoid the T1190
  hub and a leakage guard excluding the 39 eval signatures present verbatim in
  the training corpus.
- **A ranking bug cost 3.2 points before it was caught.** `predict()` ranked by
  IDF vote but reported `confidence` as mean similarity; `reasoner.py` re-sorts
  by confidence and silently discarded the IDF ranking. **Any resolver
  returning a ranked list must encode that ranking in `confidence` —
  nothing enforces this.**
- **`ClassifierResolver(prior_alpha=0.5)`** subtracts a class-frequency term
  from decision scores; the classifier had become the hub-collapse source
  (T1190 on 56.2% of rows it answered). Costs 0.2 micro for 6 points of
  calibration, and makes the classifier abstain more honestly (161 rows at
  45.2%, versus 253 at 42.7%).
- **Ensembling did not help** — higher-confidence-wins and agreement-voting
  both landed on the plain cascade's number.

| | micro | macro | T1190 (true 28.5%) |
|---|---:|---:|---:|
| original, with `bridge_table` | 38.0% | 18.6% | 13.4% |
| `bridge_table` removed (effort 10) | 32.7% | 13.5% | 38.5% |
| **effort 11** | **38.8%** | **21.1%** | **33.5%** |

Known and uncorrected: the 39-row train/eval leakage also inflates
`tier2_combined` slightly, since it trains on those rows.

## 12. Corpus diversity — Elastic adopted, Splunk rejected — 38.8% / 22.2% — `attack_mapper/elastic_corpus/findings.md`, `attack_mapper/splunk_corpus/findings.md`

Effort 11 named the highest-leverage remaining work: `tier2_combined` and
`knn_corpus` answer 350 of 397 scoreable rows and both draw on the same
ET-dominated corpus (26,644 of 29,933 rows covering only 45 techniques). Two
public ATT&CK-labeled rule sets were built into corpora in that same format
and measured one at a time, against a baseline first re-run on unchanged code
(reproduced effort 11 exactly: 154/397, 21.1% macro, T1190 33.5%).

| corpus  | rows  | distinct techniques | top-5 share | adopted |
|---------|------:|--------------------:|------------:|---------|
| Elastic | 1,892 |                 444 |       15.3% | **yes** |
| Splunk  | 2,140 |                 376 |       15.1% | no      |

| config | micro | macro | T1190 share (true 28.5%) |
|---|---:|---:|---:|
| baseline (ET+Sigma) | 38.8% | 21.1% | 33.5% |
| **+Elastic** | 38.8% | **22.2%** | **29.0%** |
| +Elastic +Splunk | 39.3% | 21.8% | 27.5% |

**Elastic: +1.1 macro and a 4.5-point calibration gain for 6% more rows**,
with micro flat — predicted before the run and confirmed on all three counts,
since class *coverage* is a calibration problem rather than a top-line one.

**Splunk rejected despite owning the best micro number.** +0.5 micro is 2 rows
of 397 on a set where only 208 rows carry an explicit reviewer verdict, and
it cost 0.4 macro. New
per-corpus instrumentation (`knn_resolver.neighbour_source_counts`, plus
`validate.py`'s top-1 accuracy split by winning corpus) shows why: Splunk's
retrieved neighbours won 20 top-1 rows at **0/20**, and crowded Elastic's
contribution down from 27.9% to 15.2%. The micro tick came from the extra
classes promoting 29 rows from retrieval to the stronger classifier layer, not
from Splunk retrieval working. This is exactly the artifact-vs-signal
distinction effort 8 got wrong, caught here by instrumentation rather than
inspection after the fact.

Generalisation for future corpora: diversity stats did not predict usefulness
(both corpora were similarly diverse). Register did — Elastic names describe
the observed event, Splunk names describe an analytic over a data model, and
only the former shares vocabulary with network IDS signatures. Check
per-corpus retrieval accuracy before adopting.

## Current bottom line

**38.8% top-1 / 22.2% macro (effort 12)** is the current number: the best
macro this project has measured, achieved *without* `bridge_table`.

Read the history as two phases. First, successive measurement fixes brought the
reported number *down* as inflation was removed — 53.8% (narrow, partly
circular 80-row sample) → 38.0%/34.1% (500-row blind-labeled) → 32.7%
(`bridge_table`, structurally capped, removed). None of those drops were code
regressions. Then effort 11 raised it back to 38.8% with genuine improvements:
retrieval against labeled rule text instead of MITRE prose, plus class-prior
correction on the classifier.

So the pipeline now scores slightly better than its original headline
(38.8% vs 38.0% micro, 22.2% vs 18.6% macro) while resting on none of what
made that original number untrustworthy. **53.8% was never a real ceiling** —
it was two measurement artifacts stacked.

Effort 12 then took the corpus-diversity lever the bottom line had flagged:
+1.1 macro and a 4.5-point calibration gain from Elastic, with the same lever
*rejected* for Splunk on per-corpus evidence. Both dominant sources still have
headroom — `tier2_combined` and `knn_corpus` answer 351 of 397 scoreable rows
at 43.1% and 27.3% — and neither is capped the way `bridge_table` was, but the
cheap corpus wins are now largely taken: the next corpus should be chosen on
register match, not on diversity stats. Non-embedding, non-LLM signal remains the only thing that has
actually helped in this branch: SAGE-internal signal (declared tags +
`MicroAttackStage` bridge) and a broadened training corpus compose cleanly
because they resolve disjoint rows. Every embedding/similarity-based method
tried anywhere in this research branch (zero-shot ATTACK-BERT/MiniLM, kNN,
Tier 2 TF-IDF/MiniLM/ATTACK-BERT, Tier 2 combined, Layer A in the HF
pipeline) tops out under 40% top-1 on its own — and Layer D, the one piece
explicitly designed to add reasoning on top of everything else, has not
produced one genuine improvement across 3 models / 2 reasoner designs
(effort 6's full-override regression, effort 7's off-list-answer regression,
effort 8's headline "win" that turned out to be majority-class collapse).
Every accuracy gain in this research branch that survives scrutiny has come
from harvesting or combining existing structured signal, not from any
model — embedding, classifier, or LLM — reasoning freshly over rule text.

## What's not done

- **Scoring counts rejected labels as ground truth — found in effort 12,
  convention now ruled, code not yet changed.** 208 of the 500 rows carry an
  explicit `reviewer_verdict` (165 `1`, 43 `0`). `validate.py:190` treats *any*
  non-empty verdict as "confirmed", so the 43 rejections are scored against the
  very `proposed_technique` the reviewer rejected. 36 of those 43 are
  scoreable, and **22 are currently counted as HITs**.
  **Ruled 2026-09-11:** `1` = reviewer agrees, include the row; `0` = reviewer
  disagrees, exclude the row from evaluation entirely. Applying that moves the
  headline from 38.8% (154/397) to **36.6% (132/361)** — a measurement
  correction of the same kind as efforts 9 and 10, not a regression. Effort
  12's Elastic result is unaffected (measured as a delta on a constant set, so
  the bias cancelled). **Still to do:** encode the rule in `validate.py`, and
  define the values in `label_queue/CONVENTION.md`, which documents the column
  as starting empty but never says what its values mean.
  Worth noting for the label review: 30 of the 36 are `ET SCAN`-style rows
  proposed as `T1046`, so this is one convention disagreement (`T1046` vs
  `T1595`/`T1018` for external service scanning), not 36 independent errors —
  the same shape as the `ET POLICY` gap below.
- **Ground truth depth — half-solved by effort 9, and the remaining half is
  the hard half.** The set is now 500 rows (397 scoreable), clearing the
  brief's 200+ row count. But **only 208 rows carry an explicit reviewer
  verdict**; the other 292 are unreviewed. Note the reported "human-confirmed"
  count (308) counts the original 100 `hand_audit` rows as confirmed purely by
  provenance — `validate.py:190` defaults their `label_source` to
  `hand_audit` — even though their `reviewer_verdict` columns were never
  filled in. By the standard this section itself sets (an unreviewed label is
  a hypothesis), the defensible count is 208, not 308. What exists now is a
  *review queue* with measured 88-96% self-consistency
  (`label_queue/CONSISTENCY.md`), which makes human confirmation fast; it is
  not ground truth. **Start with the `ET POLICY` executable-download
  convention gap** — is a routine binary transfer benign policy or `T1105`? —
  which accounts for most of the residual inter-pass disagreement and, once
  ruled on, applies to a whole class of rows at once.
- **Two missing commas in `signatures/alert_signatures.py`** (lines 671, 821)
  fuse four real signatures into two unmatched strings, so those alerts get
  `unknown_mapping` instead of `END_POINT_DOS`/`HOST_DISC`. Found in effort 9,
  **unfixed** — it is production-pipeline code, out of scope for this research
  branch, and changing stage classification changes AGs, so it needs its own
  branch and the `changes-ags` PR label.
- **LLM reasoning layer has not produced a genuine improvement in 3 tries.**
  Effort 6 (`llama3.2:3b`, full-override design) regressed 20 points.
  Effort 7 fixed the gating/blending bugs and retried with `llama3.1:8b`:
  still regressed 8 points, traced to the LLM proposing a technique outside
  the candidate list at high confidence. Effort 8 tried `qwen2.5:7b-instruct`
  with the same fixed reasoner and got a headline 62.5% — but it's an
  artifact of collapsing to guess `T1190` (the modal class) almost every
  time, not better reasoning; would likely hurt on a less `T1190`-heavy
  corpus. Two untried next steps, neither sufficient alone: (a) reject/
  down-weight off-list `technique_id`s (catches effort 7's failure, not
  effort 8's); (b) penalize low-specificity or repeated-technique reasoning
  to catch modal-class collapse (catches effort 8's, not effort 7's).
- **The classifier-stacking gain rests on a 5-row sample** (effort 5, the
  18 rows that used to fall through to embedding, of which the classifier
  claims 5). Directionally promising, not a stable estimate. Effort 9's set
  now gives the classifier 53 top-1 rows to be judged on instead of 5 — that
  re-scoring has not been broken out per-source yet, and is the cheapest
  remaining check.
- **Splunk/KQL/Elastic/YARA extractors** from the original HF plan were
  explicitly not built — no rules of those formats exist anywhere in this
  repo to test against.

## Where things live

```
experiments/mitre_mapping/
  STATUS.md                     # this file
  findings.md                   # effort 3's results + effort 5's stacking/reorg updates
  plan.md, generalisable mitre mapper.md   # the original HF suggestion
  validate.py, validation_report.md
  tests/                        # extractor unit tests

  attack_mapper/                # THE ACTIVE PACKAGE (effort 3 + effort 5) -- self-contained,
                                 # no imports reach outside this tree
    __init__.py, models.py, config.py
    attack_data.py               # own copy of the STIX-bundle reader
    normalize.py                 # own copy (signature-text canonicalization)
    alias_table.py                # own copy of the STIX tool/malware alias-table logic
    classifier_training.py        # own copy of the TF-IDF+LinearSVC training logic
    corpora.py                    # effort 12: the one CORPUS_PATHS tuple both the
                                   # classifier and kNN read (it is read twice inside
                                   # knn_resolver -- loader and cache fingerprint --
                                   # and a mismatch silently misaligns the leakage mask)
    mitre_client.py, ioc_resolver.py, narrative.py, knn_resolver.py,
    llm_client.py, classifier_resolver.py, reasoner.py, pipeline.py
    extractors/                  # suricata.py (primary), sigma.py, generic.py, base.py
    data/                        # own copies of every data dependency:
      enterprise-attack.json      # gitignored, large -- STIX bundle cache
      emerging-all.rules          # gitignored, large -- vendored ET ruleset
      knn_corpus_embeddings.npz   # gitignored, 44MB -- rebuilt when the corpus changes
      labeled_set_v2.csv          # effort 9's 500-row labeled/review set
      hand_audit_sample*.csv      # the original 100-row hand-audited sample
      et_labeled_corpus.csv       # the four training corpora (see corpora.py for which
      sigma_labeled_corpus.csv    #  are actually loaded -- splunk is built but not used)
      elastic_labeled_corpus.csv
      splunk_labeled_corpus.csv
      *_parse_failures.csv
    sigma_corpus/                # effort 4: how the Sigma corpus was built
      build_corpus.py, findings.md
      sigmahq/                   # third-party clone, gitignored -- see findings.md to refetch
    elastic_corpus/              # effort 12: adopted (+1.1 macro, -4.5 T1190 share)
      build_corpus.py, findings.md
      detection-rules/           # third-party clone, gitignored -- see findings.md to refetch
    splunk_corpus/               # effort 12: built and measured, NOT loaded (0/20 on the
                                  # top-1 rows its own neighbours won) -- see findings.md
      build_corpus.py, findings.md
      security_content/          # third-party clone, gitignored -- see findings.md to refetch

  archive/                       # SUPERSEDED -- kept for the record, not iterated on
    results.md, SMET_STATUS.md, bad_call_table.*, bridge_table.py, build_*.py,
    candidate_techniques.json, conflicts.csv, coverage_check.py, fetch_techniques.py,
    ground_truth.py, ground_truth_signatures.csv, merged_ground_truth_stage.csv,
    report.md, run_methods.py, score.py, techniques.json, validate_bridge.py,
    attack_data.py, bridge_table_validated.json, enterprise-attack.json   # effort 1
    tiered_approach/              # effort 2, moved wholesale, internally unchanged --
                                   # its own scripts still resolve their own relative paths
    sigma_corpus/sigma_labeled_corpus.csv   # frozen copy so tier2_classifier_combined.py
                                             # (archived) still runs unmodified
```
