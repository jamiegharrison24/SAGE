# MITRE ATT&CK mapping research — status

> **The consolidated reference for this work is [`REPORT.md`](REPORT.md).**
> This file remains the detailed record for the running index of all twenty-two efforts; read the report first.

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

Twenty-two sub-experiments have run so far, in order. Each has its own detailed
write-up; this file is the index and the current bottom line.

**Read effort 14 first.** `corpus_coverage_findings.md` is the branch's current
working explanation, and it supersedes the framing every earlier section was
written under. The short version: every lever pulled in efforts 1-13 was a
*representation* lever (better embeddings, better classifier, better text
normalisation, an LLM on top), and the binding constraint is *coverage* — the
corpus does not contain training examples for the techniques the evaluation set
actually asks about. Sections 1-13 remain accurate as records of what was run
and measured; where they speculate about *why* something failed, effort 14 is
the later and better answer.

**Read numbers by regime, not by effort number.** Five different evaluation
regimes appear below, and four separate measurement corrections have landed in
this branch's history. A score from section 5 and a score from section 13 are
not comparable and must not be ranked against each other — see "Evaluation
regimes" immediately below, which is the key to every table in this file.

## Evaluation regimes

| regime | eval set | scoreable rows | sections measured on it |
|---|---|---:|---|
| A | 80-row hand-audit sample | 80 | 3, 5, 6, 7, 8 |
| B | hand-audit, Tier 2 scored in isolation | 79 | 2, 4 |
| C | 500-row set, pre-scoring-fix | 397 | 9, 10, 11, 12 |
| D | 500-row set, corrected `reviewer_verdict` | 361 | 12 (re-run), 13 — **current** |
| E | 773-signature propagated ground truth | varies | 1 |

Regime A is narrow and partly circular: its `current_gt` was derived through
the same bridge table the pipeline's dominant source keyed off. Regime C→D is
the 2026-09-11 `reviewer_verdict` correction (verdict `0` = reviewer rejected
the mapping = row excluded), which moved the headline 38.8% → 36.6%.

**Macro-average was not measured before section 9** — `validate.py` only began
reporting it at effort 9. Blank macro cells in sections 1-8 mean not-measured,
not zero. Per effort 14 §7, macro and the mid/tail bucket accuracies are now
the numbers to watch; micro is dominated by three head classes and moves for
reasons unrelated to whether the pipeline improved.

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

### Caveat added 2026-09-11 — the Elastic evidence did not survive the scoring fix

Re-running under the corrected `reviewer_verdict` rule (Step 0 of
`entity_normalisation_plan.md`) moves the per-corpus retrieval accuracies:

| winning corpus | before (397 scoreable) | after (361 scoreable) |
|---|---:|---:|
| elastic | 12/43 = **27.9%** | 2/30 = **6.7%** |
| et | 19/77 = 24.7% | 19/76 = 25.0% |
| sigma | 17/56 = 30.4% | 16/52 = 30.8% |

ET and Sigma barely move. **Elastic collapses**, because 10 of its 12 apparent
hits were on rows the reviewer had rejected. The claim this section rests on —
"Elastic rows win top-1 at an accuracy comparable to Sigma and better than ET,
so this is new signal rather than a reweighting artifact" — is therefore no
longer supported by the evidence quoted for it.

What still stands: the aggregate macro gain (+1.1) and hub-share improvement
were measured as a delta across a constant evaluation set, so the rejected-row
bias sat on both sides and cancelled in *that* comparison. What does not stand
is the per-source attribution used to argue the gain was real signal.

**Resolved same day** by re-running the ET+Sigma baseline under corrected
scoring:

| config (corrected scoring, 361 scoreable) | micro | macro | T1190 share |
|---|---:|---:|---:|
| ET + Sigma | 37.1% (134) | 20.9% | 36.3% |
| **+ Elastic** | 36.6% (132) | **22.2%** | **31.3%** |
| delta | **-0.5** | **+1.3** | **-5.0** |

**The adoption decision holds, but the stated mechanism was wrong.** Effort
12 claimed Elastic supplied *new signal*, evidenced by its rows winning top-1
at accuracy comparable to Sigma. Under corrected scoring Elastic's own
retrieval accuracy is 6.7% — far *worse* than ET (24.3%) and Sigma (26.6%) —
yet macro still improves 1.3 points and hub share falls 5.

So Elastic is helping by **diluting the T1190 hub in the IDF-weighted voting
pool**, not by contributing better neighbours. That is precisely the
"reweighting artifact" the `neighbour_source_counts` instrumentation was built
to detect, and here it is the actual mechanism. It remains a real, reproducible
benefit — reducing hub collapse is what the corpus-diversity work set out to do
— but it is a calibration effect, not a retrieval-quality one, and it costs 0.5
points of micro.

Kept on that basis. The lesson generalises: a corpus can improve macro and
calibration purely by changing the class-prior denominator, without its own
retrievals being any good.

## 13. Entity-aware normalisation — built, measured, **negative** — `attack_mapper/entity_ner/findings.md`, `entity_normalisation_plan.md`

The hypothesis: the statistical layers match on surface wording, so `nmap` and
`masscan` are unrelated strings to them. Marking entity spans should let the
model learn "a TOOL appears here" instead of memorising every tool name.

Built in three parts — a 94,786-entry gazetteer (MISP galaxy + IANA + CPE), a
GLiNER v2.1 zero-shot NER pass, and an `<ENTITY>` marker injected inside
`canonicalize()` so corpus and query text are augmented identically.

**Result: macro down, hub share up, in both measured arms.**

| arm | micro | macro | T1190 share |
|---|---|---|---|
| baseline (off) | 36.6% | **22.2%** | 31.3% |
| `gliner_only` | 35.5% | **19.4%** | 33.8% |
| `intersection` | 37.1% | **21.3%** | 33.2% |

`intersection`'s +0.5 micro is 2 rows of 361 — inside noise, and arriving with
macro down and hub share up, which is the combination the plan pre-registered
as modal collapse rather than a gain. Not banked.

**Why it failed is structural, and was derivable before the corpus pass.**
Augmentation preserves the distinguishing token: `nmap <ENTITY> scan` and
`masscan <ENTITY> sweep` still differ exactly where it matters. All the marker
adds is a token present in 42% of rows, with the low IDF that implies, applied
near-uniformly — which nudges every row slightly toward every other, including
toward the hub. Only *replacement* makes two tools look alike, and replacement
was rejected earlier on risk grounds. Augment-not-replace and generic-not-typed
were each defensible alone; together they cannot deliver the generalisation
that motivated the work.

Three of five merge rules were eliminated *before* any scoring run, by
`entity_ner/marker_rate.py`: `union`, `gliner_primary` and `gazetteer_only` tag
~90% of corpus rows, making `<ENTITY>` a constant rather than a feature. That
diagnostic cost seconds and saved three `validate.py` passes; it is the reusable
part of this effort.

**Two validity checks passed before the negative was accepted**, which is what
makes it a result rather than a plumbing failure: `canonicalize()` with the
tagger off was diffed byte-for-byte against the committed normaliser over all
31,825 corpus strings (**0 differ**), and both arms logged **0 NER cache
misses**, so queries and corpus rows were tagged from the same artifact with no
train/inference asymmetry.

**The two models this effort left unrun have since been run at span level** —
`entity_ner/comparison_findings.md`, consolidated in `REPORT.md` §5. NuNER Zero
wins rare-entity recall at every document-frequency cut but is less precise at
every threshold (32% vs 44% strict) and its false-positive strings occur in
19.4% of corpus rows against GLiNER's 2.5%; SecureBERT2.0-NER's `System` type
does cover software products — the plan's recorded open question — but 65% of
its output lands in a catch-all `Indicator` class, and it is closed. Two
corrections came out of the same pass: this effort's 47%/73% per-entity
precision was **not reproducible** (`entity_ner/trial_sample.csv` ships an empty
`verdict` column; verdicts now live in `entity_ner/verdicts.py`), and its
explanation of its own null — that the surviving spans were already
high-frequency protocols — does not survive measurement: by corpus DF only
`HTTP` (12.3%) is, against `SMB` 0.15% and `NTP` 0.009%. Effort 14's coverage
explanation supersedes it either way. Still open: **replacement** of rare
entities only, pointed at GLiNER at 0.85 rather than NuNER.

Kept, off by default (`Settings.use_entity_tagging = False`). The machinery,
the frequency diagnostic and one genuine bug fix are all reusable:
`knn_resolver._corpus_fingerprint()` now hashes the normaliser identity. That
trap was live — the 49MB embedding cache is keyed on corpus files and model
name, neither of which a normalisation change touches, so every arm here would
have silently scored the *old* normaliser with entirely plausible numbers.

## 14. Error analysis — the binding constraint is coverage, not representation — `corpus_coverage_findings.md`

Diagnosed the 229 misses in the 36.6%/22.2% baseline. **This supersedes "hub
collapse" as the working explanation for this branch and re-reads every prior
negative result under one cause.**

**Hub collapse is already solved, and this file previously cited a stale base
rate.** The pipeline predicts `T1190` on 113/361 rows; the true `T1190` count is
also 113/361 — exact calibration. The 28.5% base rate quoted in sections 11-13
was measured pre-Step-0; the `reviewer_verdict` fix moved it to 31.3%. So
effort 13's entity work targeted a problem the scoring fix had already
dissolved, which explains its null better than the structural argument filed in
`entity_ner/findings.md`.

**Accuracy tracks training-example count, not text quality:**

| bucket | eval examples | classes | rows | top-1 |
|---|---|---:|---:|---:|
| head | >=20 | 3 | 189 | 43.9% |
| mid | 3-19 | 21 | 137 | 31.4% |
| tail | <=2 | 27 | 35 | 17.1% |

**Smoking gun.** All 21 `ET DOS` rows predict `T1495` Firmware Corruption. The
corpora contain exactly **one** row labeled `T1495`, text "Cisco Denial of
Service". Every `ET DOS` title normalises to contain "denial of service", so
that single mislabeled row wins the neighbourhood for the whole category —
because there is nothing else to retrieve.

**Supply versus demand:**

| technique | eval rows | corpus rows |
|---|---:|---:|
| `T1595.002` | 44 (12.2%) | 8 |
| `T1499` | 32 (8.9%) | 9 |
| `T1498` | 12 (3.3%) | 10 |

Three techniques are 24.4% of the eval set with 27 training examples between
them, out of 31,825. ET is 83% of the corpus but carries only 45 techniques
(68% of it is `T1190`/`T1071`/`T1568`); Sigma and Elastic carry the diversity
but in the wrong register — Windows/host and cloud/endpoint, against a
network-IDS eval set. The corpus is large and almost orthogonal to the test
distribution.

**One cause covers every negative in this branch:** Splunk (0/20, host
register), Elastic (6.7% own retrieval, helping only via IDF dilution, endpoint
register), MISP galaxy (1.0% hit rate, host-side malware names), entity
normalisation Steps 1-3 (normalising text cannot create training examples for a
class that has eight), and Layer D's three failures (an LLM cannot retrieve what
is not there).

**The trap in the obvious fix.** Labelling ET's own `ET DOS` category as
`T1498`/`T1499` by rule would supply the missing examples immediately — but
`CONVENTION.md` instructs human labellers with that same rule, so scoring
against those labels is scoring the pipeline against a copy of its own input.
That is the `bridge_table` circularity effort 9/10 removed for capping at 34.8%.
If a category rule builds training data, the eval rows in that category must be
held out or the number is meaningless.

**The number to watch is no longer micro** — it is mid/tail bucket accuracy
(31.4% / 17.1%) and the supply column above.

## Current bottom line

**36.6% top-1 / 22.2% macro** on regime D (361 scoreable rows, 43 excluded),
after the 2026-09-11 `reviewer_verdict` scoring correction. That is the current
headline, but effort 14 says it is the wrong number to optimise: micro is
carried by three head classes. The honest summary of pipeline quality is
**43.9% head / 31.4% mid / 17.1% tail**, and the tail is where the technique
diversity lives.

**How to read the history.** Two phases, then a reframe.

*Phase 1 — inflation removed.* 53.8% (regime A: narrow, partly circular 80-row
sample) → 38.0%/34.1% (regime C: 500-row blind-labeled) → 32.7% (`bridge_table`
removed as structurally capped). None of those drops were code regressions; all
four were measurement corrections. **53.8% was never a real ceiling** — it was
two measurement artifacts stacked.

*Phase 2 — genuine gains.* Effort 11 raised it to 38.8% by retrieving against
labeled rule text instead of MITRE description prose, plus class-prior
correction on the classifier. Effort 12 added Elastic for +1.3 macro and a
5-point calibration gain. So the pipeline now scores better than its original
headline (36.6%/22.2% vs 38.0%/18.6%, across a scoring correction) while
resting on none of what made that original number untrustworthy.

*Phase 3 — the reframe (effort 14).* Every remaining lever tried was a
representation lever, and they have all returned null: three LLM models across
two reasoner designs, four encoder swaps, entity-aware normalisation Steps 1-3,
and two of three candidate corpora. The binding constraint is that the training
corpus does not contain examples of the techniques the eval set asks about.
**No representation lever can fix a coverage problem**, which is why the null
results are so uniform.

What has actually worked, every time, is harvesting or combining existing
structured signal — vendor-declared ATT&CK tags (71.8-81.8% precision), SAGE's
own `MicroAttackStage`, and a broadened training corpus — because those add
information rather than re-encoding what is already there. Nothing in this
branch has been improved by a model reasoning freshly over rule text.

## What's not done

### Untried levers, in priority order

Ordered per effort 14, coverage-first. This supersedes any ordering implied by
earlier sections or by `entity_normalisation_plan.md`, which still names
"section 8 classifier modernisation" as the remaining lever — written before
the coverage diagnosis.

1. **Find a labeled corpus in the right register** — network-IDS rules carrying
   genuine ATT&CK metadata. Select on *register match*, not diversity stats:
   effort 12 showed diversity does not predict usefulness (Splunk and Elastic
   were similarly diverse; Splunk retrieved 0/20). Check per-corpus retrieval
   accuracy before adopting. Subject to effort 14's circularity trap.
2. **Harvest ET/ETPRO/Snort declared tags more aggressively** — real vendor
   metadata, so not circular, and the highest-precision source in the branch
   (71.8-81.8%). Tier 0 recovers only 39 rows today; just 11 of 62 matched
   bodies carry a tag, and ETPRO/Snort sources were never exhausted.
3. **Deepen the reviewed label set** — only 208 of 500 rows carry an explicit
   reviewer verdict. Start with the `ET POLICY` executable-download convention
   ruling; it settles a whole class at once and is the residual inter-pass
   disagreement in `label_queue/CONSISTENCY.md`. Detail in the bullets below.
4. **LLM fixes (a) and (b) together, or not at all** — (a) reject/down-weight
   off-list `technique_id`s catches effort 7's failure; (b) penalize
   low-specificity or repeated-technique reasoning catches effort 8's modal
   collapse. Neither is sufficient alone, and they are complementary, not
   alternatives. Note effort 14 predicts a limited ceiling here regardless: an
   LLM cannot retrieve what is not in the corpus.
5. **Section 8 classifier modernisation.**
6. **Cheapest remaining check** — re-score the classifier per-source on its 53
   top-1 rows (effort 9 gave it 53 rows instead of the 5-row sample effort 5
   flagged as unstable; never broken out).

Out of scope here: the Splunk/KQL/YARA extractors (no rules of those formats
exist in this repo to test against) and the two missing commas in
`signatures/alert_signatures.py` (production code — own branch, `changes-ags`
label). Both are detailed in the bullets below.

### Backlog detail

- **Circle back: `intersection` vs `gliner_only` (NER-only) merge rule, under
  typed markers.** Measured 2026-09-21, same session as effort 17, not yet
  written up formally. Dropping the gazetteer-agreement filter (keeping every
  NER span, not just ones the dictionary corroborates) was expected to help —
  it looks like pure information loss reading `intersection`'s dropped spans
  in isolation (e.g. a correctly-typed `PLATFORM` span on "Windows" gets
  discarded because the gazetteer has no matching entry). Measured the
  opposite: `gliner_only` scores worse than `intersection` on every axis,
  generic or typed (micro 128/361 vs 132/361; macro 19.8-21.1% vs 20.5-21.5%;
  mid-bucket 27.0-27.7% vs 29.2%). One flipped tail-bucket row under
  `gliner_only`/typed is a source change, not just a confidence wobble
  (`supervised_classifier` 0.26 hit → `knn_corpus` 0.21 miss landing on the
  modal `T1190` — the hub-collapse pattern §6.4/§6.5 already flag elsewhere).
  Also visible in the same numbers, not yet separately investigated: **every**
  tagging configuration (both merge rules, generic or typed) drops mid-bucket
  accuracy below the no-tagging baseline (31.4% → 27.0-29.2%) — a bigger,
  more consistent effect than the generic-vs-typed question the numbers were
  gathered to answer. Worth its own writeup (`bucket_accuracy.py` on
  `validation_report.md`, `validation_report_entity_gliner_only_securemodernbert*.md`,
  `validation_report_entity_intersection_securemodernbert*.md`) before
  concluding anything — this note is the raw finding, not the analysis.

- ~~**Scoring counts rejected labels as ground truth**~~ — **DONE 2026-09-11**
  (effort 13, "Step 0"). The rule is now implemented in `validate.py` and
  defined in `label_queue/CONVENTION.md`. Original entry kept below for the
  reasoning; the headline has carried the corrected 36.6% since.

  208 of the 500 rows carry an
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


## 15. Replace-mode (rare-only) entity normalisation — built, measured, **negative** — `attack_mapper/entity_ner/replace_prereg.md`

REPORT.md §8 item 7: replace *rare* entity spans only, leaving high-frequency
ones alone — the one variant implementing effort 13's original hypothesis,
since augment provably changes no distance between two rules.

Built as a second path (`entity_tagger.replace_spans`), not a change to
`inject_markers`, so effort 13's 19.4%/21.3% stay reproducible.

**Result: negative, decisively.** Macro **16.4-18.3%** against the 22.2%
baseline, and ~1-3 points *worse* than effort 13's augment. Pre-registration
required >= 23.2%; no arm came close, so the outcome was never a judgement
call.

| arm | micro | macro | vs baseline |
|---|---:|---:|---:|
| baseline (off) | 36.6% | **22.2%** | - |
| effort 13 augment | - | 19.4% | -2.8 |
| `drop` @ 0.005 / 0.01 / 0.02 | 33.8 / 33.5 / 33.5% | **17.2 / 16.4 / 16.4%** | -5.0 / -5.8 / -5.8 |
| `marker` @ 0.005 | 34.6% | **18.3%** | -3.9 |
| `sentinel` @ 0.005 | 33.0% | **17.2%** | -5.0 |

**The hypothesis is falsified, not merely unsupported.** Effort 13 argued
augment failed *because* it left the rare token in place and changed no
distance, and that replacement would fix it. Replacement is worse than augment,
and degradation rises monotonically with the share of spans replaced
(25.7% -> -5.0, 29.9% -> -5.8, 32.7% -> -5.8). The rare tokens were carrying
signal, not blocking similarity. §8 item 7 is closed.

**Style is second-order, and `<ENTITY>` was not the problem.** The three styles
span 17.2-18.3% at a fixed cutoff — inside the noise band the pre-registration
set — and `marker` is nominally *best*, i.e. the style the tokenization
argument predicted worst. `drop` removes the marker entirely and still loses to
keeping it.

**Follow-up: the same defect in `<CVE>`/`<IP>`/`<HEX>`/`<VERSION>` is
negligible.** Those run in every measurement including the baseline, so they
were tested with collision-free replacements: micro 36.6% -> **36.8%**, macro
22.2% -> **22.3%**. One row. The collapsing job always worked; only collision
with literal `cve`/`version` (0.04-0.05% of rows) was at stake. Kept as
`--reserved-placeholders`, off by default -- every number on this branch
assumes off and stays valid.

Four supporting measurements stand on their own, independent of the arms:

1. **The DF gate holds.** `df_table.py` measures n-gram document frequency over
   the 31,825-row corpus and reproduces the figures effort 13 and §8 item 7
   were written from (`SQL` 12.06%, `Injection Attempt` 12.02%, `URI` 0.62%,
   `RDP` 0.77%, `SMB` 0.15%). Across all 14,675 spans, `SQL`/`Injection
   Attempt`/`HTTP`/`DNS` are replaced at **no** cutoff.
2. **GLiNER-at-0.85 spans are NOT "mostly rare by construction"** — only 33.2%
   are replaceable even at a 5% DF cutoff. This premise, written into §8 item 7
   and this effort's own plan, is false: the 0.85 span set is not a proxy for
   the rare entities.
3. **`<ENTITY>` is not a reserved symbol to the classifier** — and this applies
   to the *existing* normaliser, not just this effort. The word vectorizer uses
   sklearn's default `\b\w\w+\b`, which strips non-word characters, so
   `<entity>` reads as the ordinary word `entity` (and `<CVE>` as `cve`,
   `<VERSION>` as `version`). Hence a three-way style sweep — `marker` / `drop`
   / `sentinel` — over whether a placeholder should be left behind at all.
   Typed markers stay rejected (~1 in 5 mistyped, settled 2026-09-11).
4. **Baseline reproduces** under the bumped `NORMALIZER_VERSION`: micro 36.6%,
   macro 22.2%, identical to `validation_report.md`.

**Two silent-failure traps found and closed** (both yield a plausible number
rather than an error): a partial spans artifact passes `_check_artifact_meta`
and scores like the off-baseline — closed by `assert_complete()`; and `drop`
can erase a title that *is* one entity to an empty all-zero TF-IDF row that
still predicts confidently — floored, and measured to never fire on this
corpus.

Falsification fixed in advance: success requires macro **≥ 23.2%**
(baseline + 1.0); within ±1.0 is noise, and an arm winning only where
`n_replaced` ≈ 0 is disqualified. Per effort 14, this is expected to close
out a hypothesis rather than move the headline.

## 16. A non-generic (cyber-domain-trained) NER model — `attack_mapper/entity_ner/comparison_findings.md` (addendum)

Per explicit supervisor direction, evaluated `attack-vector/SecureModernBERT-NER`
(ModernBERT-large fine-tuned on 502k spans, 22 cyber-specific entity types) at
span level, against the same 30-title sample and pre-registered gate as
effort 13's GLiNER/NuNER/SecureBERT2.0 comparison. Unlike GLiNER/NuNER
(generic zero-shot models given cyber labels at inference) and unlike
SecureBERT2.0-NER (cyber-pretrained but a 5-class schema that collapses to a
65%-catch-all `Indicator`), this model is both domain-trained and
fine-schema'd enough not to collapse.

**Result: the first model in this branch to clear the pre-registered gate on
both axes at once** — 59% strict / 69% lenient precision (vs. GLiNER 44%/56%,
NuNER 32%/48%), 17 rare (DF<1%) true positives (vs. GLiNER 13, NuNER 16), at a
1.63% corpus-DF noise burden — *lower* than GLiNER's 2.45%, and 12x lower than
NuNER's 19.4%. It wins the recall-vs-cost tradeoff that made GLiNER and NuNER
each dominant on only one axis.

**Does not change effort 14's conclusion.** This is still a representation
lever (better span recovery on titles); the binding constraint remains corpus
coverage (`T1595.002`: 44 eval rows, 8 corpus rows), and no NER model creates
training examples where none exist. Span-level only — no `build_spans.py`
corpus pass, no `marker_rate.py` frequency screen, no `validate.py` arm. It is
now the strongest of the three candidates to spend the one `replace_prereg.md`
run on (see comparison_findings.md's addendum for the full breakdown,
including two measured weaknesses: type/boundary slippage on compound
vendor+product names, e.g. `IBM Tivoli Endpoint`, and false hits on ATT&CK
tactic names used as descriptive English rather than as named references).

**Confirmed on a second, larger, independent sample (100 titles, seed 42, vs.
the original 30).** SecureModernBERT-NER still wins strict/lenient precision
(55%/69% vs. GLiNER 50%/68%, NuNER 37%/53%), still wins rare-entity recall at
every DF cut (66/66 TPs rare vs. GLiNER 52/60, NuNER 59/72), and still has by
far the lowest noise burden (10.99% vs. GLiNER 18.34%, NuNER 49.82% — all
three rose sharply at 3x the sample size, but the ranking held). One bug
caught and fixed in the process: the model's span text carries a leading
space the DF lookup didn't strip, which silently inverted the rare/common
split on the first pass (54 common vs. 12 rare) before being spotted via
`df_table.py --show` on the individual strings and corrected. Full record:
`entity_ner/comparison_findings.md`'s "Robustness check" section,
`entity_ner/verdicts_n100.py`.

**Taken all the way to `validate.py`, and the pipeline result is null.**
`entity_tagger.py` was generalised to a `ner_backend` registry so either
model can drive `--entity-tagging` (own spans artifact each, `gliner` still
the unchanged default). Full corpus pass (`build_spans.py --backend
securemodernbert`, 32,273 texts, 29.9 min) tags 89.4% of texts — far more
than GLiNER's 42.0% — which means four of five merge rules are immediately
near-constant on the corpus (`marker_rate.py` pre-screen: union 97.5%,
gazetteer_only/NER-only 89.5%, only `intersection` at 28.9% is informative).
`validate.py --entity-tagging intersection --ner-backend securemodernbert`:
**36.6% micro (132/361) — the identical row count as the untagged baseline —
21.5% macro (vs. 22.2% baseline, inside the ±1.0 noise band), T1190 share
flat (31.6% vs. 31.3%).** Not a small win or a small loss: the same 132 rows
score correctly with or without the tagging. This is effort 14's prediction
confirmed for the strongest NER model measured on this branch, not just
GLiNER — span quality was never the bottleneck, corpus coverage is, and a
better span recognizer cannot manufacture training examples for
`T1595.002`/`T1499`/`T1498` (44/32/12 eval rows vs. 8/9/10 corpus rows) no
matter how much cleaner its tags are. Kept in the codebase, off by default;
not adopted as a pipeline change. Full record:
`entity_ner/comparison_findings.md`'s "Pipeline integration" section.

## 17. Typed markers — one sentinel per entity type instead of generic `<ENTITY>` — **negative** — `attack_mapper/entity_ner/typed_markers_prereg.md`

Every marker on this branch so far, including effort 16's SecureModernBERT-NER
run, has been the same generic `<ENTITY>` regardless of the source model's
type (`ORG`, `PRODUCT`, `TOOL`, ...). That was a deliberate 2026-09-11 decision
(`entity_ner/replace_prereg.md`, "What was considered and rejected"), reasoned
from GLiNER/the gazetteer's ~20% type-mistake rate — never measured, and never
revisited for SecureModernBERT specifically, whose fixed 22-label schema is
the reason it clears the pre-registered gate at all. Per explicit direction,
reopened for SecureModernBERT only (GLiNER is no longer in active use).

Implemented as an opt-in `EntityTagger(typed_markers=True)` path: `qqe_<type>qq`
sentinels (not literal `<TYPE>` — the same angle-bracket-stripping collision
`MARKER`/`SENTINEL` already document applies worse to a hyphenated type like
`MITRE-TACTIC`, which would split into two tokens), gated on a spans artifact
storing per-span types (`build_spans.py`'s new `has_types` field — GLiNER's
artifact format is untouched). `entity_tagger.py`, `build_spans.py`,
`validate.py` (`--typed-markers`), `marker_rate.py` (`--per-type`), and
`bucket_accuracy.py` (new: head/mid/tail bucket accuracy from a report,
reusable beyond this one experiment) all updated;
`tests/test_entity_typed.py` covers the silent-failure invariants (untyped
artifact read in typed mode must raise, not degrade; fingerprint separation;
sentinel collision-freedom). Full corpus rebuild (32,273 rows) took 4.9 min
on a GTX 1660 Ti after installing a CUDA `torch` build — this machine had one
sitting unused behind a CPU-only `torch` install, which projected 45-75 min.

Per-type frequency screen cleared first (no type near-constant, unlike the
89.4%-of-corpus generic marker). `validate.py --entity-tagging intersection
--ner-backend securemodernbert --typed-markers`, matched against effort 16's
generic-marker run at the identical configuration: **micro bit-identical**
(132/361, same numerator), macro 21.5%→20.5%, and per the pre-registered
mid/tail-bucket criterion — **mid (137 rows, the stable bucket) dead flat at
+0.0 pt**; tail (35 rows) moved -2.9 pt but traces to exactly one row
flipping between two sub-0.05-confidence `knn_corpus` guesses, i.e. noise in
too small a bucket to read as signal (effort 5's mistake, avoided). Does not
change effort 14's conclusion: a marker's type cannot manufacture a training
example the corpus lacks, so there was nothing for a more informative marker
to disambiguate among. Kept in the codebase, off by default; not adopted.

## 18. Full technique coverage of the observed alert data — `label_queue/labeled_batch09-14.csv`

Built for the **AIF-vs-ATT&CK downstream study**, not for mapper accuracy. The
research question is what happens to SAGE's attack graphs when alerts map to
ATT&CK instead of the Action-Intent Framework (`MicroAttackStage`), and that
needs a *working* mapper as an assumption — an oracle condition — for every
signature that actually fires. Train/test leakage is therefore not an
objection here: these labels must never be reported as a mapper accuracy
number, and that is the only discipline the oracle framing requires.

**262 new `model_proposed` labels, taking the observed alert data from 58% to
100% technique coverage** — all 530 distinct signatures across all three
datasets, covering all 1,431,663 alert records. 223 of the 262 are scoreable
(33 distinct values; the rest are `(none)`/`ambiguous`/tactic-only declines
per `CONVENTION.md`'s grammar). Labelled from signature text plus vendor rule
body (classtype, CVE and reference fields), with `mitre_technique_id`
redacted per the blind rule.

**A parsing bug found and fixed mid-way, worth recording as a trap.** The
three alert datasets use **three different JSON schemas**, and a reader
written against one silently returns zero rows for the other two:

| dataset | records | signature path |
|---|---:|---|
| `cptc-2017` | 47,876 | `result['alert.signature']` |
| `cptc-2018` | 331,554 | Splunk export — inside the `_raw` JSON string |
| `ccdc` | 1,052,233 | native Suricata EVE — `alert.signature` nested dict |

The first pass of this work parsed only `cptc-2017` and reported "168 unique
signatures, 100% coverage". The real figure is **530 unique signatures**; the
missing 362 were not missing rows in one file but two entire datasets read as
empty, with no error raised. A second integrity check (every labelled
signature must appear verbatim in the alert data) then caught a separate
truncation error where a signature had been transcribed from a
width-truncated console listing. Both checks are cheap and both caught real
defects — run them before trusting any coverage claim.

**Distribution is not collapsed** but is genuinely concentrated by what the
data contains: `T1190` 80 (the RFI/SQLi/XSS web-exploitation cluster —
dozens of distinct ET `WEB_SPECIFIC_APPS` rules fired 41 times each by what
looks like a single scanner sweep), `T1090.003` 51 (the `ET TOR` relay
family), `(none)` 32 (Suricata protocol-parser anomalies, which are engine
events rather than attack detections), `T1595.002` 24, `T1046` 15.

**Two honest limits.** These are `model_proposed`, `reviewer_verdict` empty —
hypotheses awaiting review, not ground truth, exactly as
`CONVENTION.md` defines. And **no blind re-label consistency figure is
reported**: the convention's drift control wants ~20 rows re-labelled blind
and compared, which the labeller cannot do against its own labels in the same
session. That number needs a separate pass before the set's ceiling is known.

## 19. Training on effort 18's labels — the first genuine gain since effort 12 — `validation_report.md`

The point of effort 18's labels. 223 of the 262 became corpus rows
(`build_alert_corpus.py` → `data/alert_labeled_corpus.csv`, wired into
`corpora.py`); the 39 `(none)`/`ambiguous`/tactic-only declines were **dropped,
not coerced**, because none has a representation in a `msg,technique_ids,
tactic_ids` schema and picking a side would manufacture labels the labeller
explicitly refused to give. Tactics come from each technique's own STIX
`kill_chain_phases`, never from `MicroAttackStage` — importing the
Action-Intent Framework's judgment would defeat the point.

**Clean by construction:** 0 of the 223 appear in the eval set (verified), so
this is not the oracle/leakage case effort 18 was built for. These are
signatures that fire in the data but were never drawn into the 500-row
labelling frame.

**Regime D, against the 36.6% / 22.2% baseline:**

| | baseline | + alert corpus | delta |
|---|---:|---:|---:|
| micro | 36.6% (132/361) | **40.2% (145/361)** | **+3.6** |
| macro | 22.2% | **28.7%** | **+6.5** |
| head (3 classes, 189 rows) | 43.9% | 43.9% | **+0.0** |
| mid (21 classes, 137 rows) | 31.4% | **38.7%** | **+7.3** |
| tail (27 classes, 35 rows) | 17.1% | **25.7%** | **+8.6** |
| `T1190` share | 31.3% | 29.4% | −1.9 |

**This is effort 14's thesis confirmed in the one direction that matters.**
Head is *exactly* flat — those three classes were already saturated, so more
data cannot help them — while mid and tail, the starved buckets, move 7-9
points. Every representation lever in efforts 13-17 produced the opposite
shape or nothing at all. The new corpus also posts the **highest per-corpus
retrieval accuracy on the branch** (alert 7/15 = 46.7%, against et 23.4%,
sigma 16.7%, elastic 3.6%), which is the register-match effect §6.3 predicts:
these rows are ET/GPL signature text scored against ET/GPL signature text.

**The caveat, found by checking rather than by celebrating.** Row-level diff:
17 rows flipped MISS→HIT, 4 HIT→MISS (all four `T1190`, consistent with the
reduced hub share). Of the 17 gains, **6 have a ≥0.75-similar same-label
sibling in the new corpus** — `portmap listing UDP 111` won by my
`...TCP 111` (0.94), the SMB `asn1 overflow attempt` by my `unicode asn1
overflow attempt` (0.94), two NTP `MON_LIST` rows by my `GET_RESTRICT` row
(0.90/0.91), and so on. Excluding those six, micro is **38.5% (+1.9)** rather
than 40.2%.

So the honest mechanism is **family coverage, not learned generalisation**:
labelling one member of a signature family gets the pipeline the other
members. That is a real and useful finding — it is exactly how corpus
expansion is supposed to work, and it is the first thing on this branch to
move mid/tail at all — but the claim it supports is bounded. It predicts
improvement on techniques whose *families* you label, not on unseen families.

**And a softened form of §8's circularity trap applies.** Effort 18's labels
were written against `CONVENTION.md`, explicitly anchored on sibling
precedents from the eval set's own labelling passes. So for the near-duplicate
gains, what is being measured is partly *convention-consistency between two
labelling passes by the same kind of labeller*, not mapping ability. The 11
non-duplicate gains are the part of the result that is not exposed to this.

**Status: adopted** (`alert_labeled_corpus.csv` is in `CORPUS_PATHS`), with
the headline stated as **40.2% / 28.7%, of which +1.9 micro survives removing
near-duplicate retrieval**. The teacher behind the labels has one independent
quality measurement: **87% exact agreement with vendor-declared ATT&CK tags**
on the 54 signatures that carry both (effort 18).

## 20. Replace-mode re-measured on the current NER stack — effort 15's conclusion revised — `validation_report_entity_*_typed_replace*.md`

Per supervisor direction ("NER model integrated to identify entities in the
signature and **replace the low level artefacts**"), run on the stack actually
in use — SecureModernBERT-NER with typed markers — rather than effort 15's
GLiNER + generic `<ENTITY>`.

**This combination was previously impossible to run.** Effort 17 rejected
`typed_markers + replace_rare` in `EntityTagger.__init__`, on the reasoning
that replace was already negative and stacking two changed variables gives an
unreadable result. That served measurement hygiene and defeated the actual
requirement: the default stack could not perform the experiment it was asked
to perform. The guard is removed and `replace_typed_spans()` implements the
typed substitution — same DF gate (`SQL` at 12.1% survives, `ASA 5500 Series`
at 0.00% does not), but what is left behind is the entity's *type* rather than
one generic marker, so replacement collapses two rules onto the same string
only when they carry the same **kind** of entity.

**Regime D, against the current-corpus baseline (40.2% / 28.7%, tagging off):**

| arm | micro | macro | head | mid | tail |
|---|---:|---:|---:|---:|---:|
| baseline, tagging off | **40.2%** | **28.7%** | 43.9% | **38.7%** | 25.7% |
| `intersection` / typed / replace 0.01 / `drop` | 39.1% | 28.3% | 44.4% | 34.3% | **28.6%** |
| `intersection` / typed / replace 0.01 / `marker` | 38.5% | 26.2% | 43.4% | 35.8% | 22.9% |
| `gliner_only` / typed / replace 0.01 / `marker` | 35.7% | 20.3% | — | — | — |

**Finding 1 — effort 15's headline needs qualifying.** That effort measured
macro **16.4-18.3% against a 22.2% baseline (−4 to −6 points)** and recorded
the hypothesis as *falsified*. On the current stack the same idea scores
**26.2-28.3% against 28.7% (−0.4 to −2.5)**, and the best arm sits inside the
±1.0 noise band. Most of the original damage was **the weak NER model and the
generic marker, not the replacement idea**. "Decisively negative" becomes
"no better than not tagging", which is a materially different claim and should
be stated that way in any write-up of effort 15.

**Finding 2 — it still does not help.** Every arm is at or below baseline. The
supervisor's request is answered, and the answer is that replacing low-level
artefacts is now harmless rather than harmful, but not useful. Tail improves
(+2.9) and mid falls (−4.4); they roughly cancel.

**Finding 3 — `drop` beats `marker` (28.3% vs 26.2% macro), so the type
information is not what is paying.** Deleting the rare entity outright is
better than substituting its type sentinel. The marker token costs something
(dilution, per `marker_rate.py`'s near-zero-IDF argument) and the type it
carries does not cover that cost. This is evidence against the mechanism
effort 17 hypothesised, arriving from the replace side rather than the augment
side.

**Finding 4 — NER-only is again much worse** (20.3% macro vs `intersection`'s
26.2%), consistent with the merge-rule note in the backlog: dropping the
gazetteer-agreement filter admits noise faster than it admits signal.

Kept in the codebase, off by default; not adopted.

## 21. Substituting ATT&CK for AIF in the pipeline — built, switchable, not yet run end to end

Task 3 of the supervisor's list. Design notes are `REPORT.md` 8a; this is the
implementation record.

**Level chosen: hybrid, after tactic-only was rejected on inspection.** The
first build annotated every alert with its ATT&CK *tactic*, which fits SAGE's
digit-count severity encoding perfectly (3 low, 9 medium, 2 high). It also
collapses **13 AIF objectives into 1** (`impact`), because ATT&CK files DoS,
ransomware, defacement and data destruction under the same tactic. Since
attack graphs are generated per (victim, objective), that would merge a
denial-of-service graph with a ransomware one. Hybrid keeps technique
identity at the medium and high tiers and collapses only the low tier, giving
**4 objectives** — between AIF's 13 and tactic-only's 1.

The trade-off is genuinely two-sided and is recorded as an open question in
`REPORT.md` 8a.5 rather than settled by argument: coarser graphs are worse for
granularity but better for **alert compression**, which is one of the
evaluation metrics, and plausibly better for an analyst. All four arms are
built so it can be measured.

**A structural finding, surfaced by trying to build it.** ATT&CK *techniques*
cannot be substituted directly: AIF encodes severity in the **digit count** of
the stage integer, capping the low tier at nine stages, and the observed
signatures alone use **18** low-tier techniques. AIF's encoding is only viable
because AIF is a small closed vocabulary; ATT&CK is neither. This is why the
low tier collapses to tactics in the hybrid arm — the alternative was changing
how the pipeline derives severity, which would have meant editing the three
stages the substitution was supposed to leave alone.

**Four arms, on two axes** (`signatures/build_mitre_mapping.py`):

| arm | signatures | codes | objectives |
|---|---:|---:|---|
| `hybrid_drop` | 612 | 36 | 4 — `t1496`, `t1498`, `t1498_002`, `t1499` |
| `hybrid_catchall` | 762 | 37 | 4 — same |
| `tactic_drop` | 612 | 11 | 1 — `impact` |
| `tactic_catchall` | 762 | 12 | 1 — `impact` |
| *AIF baseline* | — | 36 | 13 |

`drop` discards the ~25% of alert volume ATT&CK has no vocabulary for;
`catchall` keeps it at low severity so the alert stream stays comparable to
AIF's. The delta between them measures how much of SAGE's graph structure
rests on alerts ATT&CK cannot name.

**Wiring: `signatures/taxonomy.py`, selected by `SAGE_TAXONOMY`** (default
`aif`, unchanged behaviour). Severity still comes from digit count in every
arm, so subsequence cutting, sink filtering and objective selection are
untouched.

**Four integration points, not the one the proposal implies.** The proposal
describes replacing "a hardcoded lookup table". The taxonomy is in fact reached
from four places, and missing any one of them fails loudly or silently:

| file | what it needed |
|---|---|
| `alert_loading.py` | signature -> stage code (the lookup the proposal names) |
| `model_learning.py` | `small_mapping[mcat]` for FlexFringe trace symbols |
| `ag_generation.py` | `micro2macro` -> node shape; ATT&CK has no macro layer, so severity picks the shape bucket instead |
| `plotting.py` | the alert histogram indexes a fixed AIF code list and crashes on any other code |

**AIF is deliberately bit-identical.** `_aif_attack_stage_mapping()` keeps the
original body, and `plotting.py` branches on `taxonomy.IS_MITRE` so the
baseline histogram renders exactly as before — an earlier version of this
change altered the AIF histogram from 36 bars to 34, which would have made the
two arms incomparable for a cosmetic reason.

**Not yet run end to end: FlexFringe is a Linux ELF and WSL is broken on this
machine** (`Class not registered`). Everything before model learning is pure
Python and does run; `compare_taxonomies.py` exercises it per arm and reports
alerts surviving, episode and subsequence counts, alphabet size and objectives
present. The S-PDFA and attack-graph stages, and therefore task 4's evaluation
diff against `docs/BASELINE_METRICS.md`, need a working FlexFringe.

### Effort 21 addendum — measured on cptc-2017 (pre-FlexFringe stages)

`compare_taxonomies.py`, all five arms, up to trace generation:

| arm | alerts | episodes | subseqs | alphabet | objectives present |
|---|---:|---:|---:|---:|---|
| AIF | 43,299 | **7,370** | **2,339** | 20 | 4: `DATA_DELIVERY`, `DATA_EXFILTRATION`, `DATA_MANIPULATION`, `NETWORK_DOS` |
| hybrid + drop | 42,441 | 4,602 | 1,354 | 16 | 3: `T1498`, `T1498.002`, `T1499` |
| hybrid + catchall | 43,299 | 4,608 | 1,354 | 16 | 3 |
| tactic + drop | 42,441 | 5,117 | 1,764 | 9 | 1: `impact` |
| tactic + catchall | 43,299 | 5,124 | 1,764 | 9 | 1 |

**Two predictions in 8a.2 and 8a.3 are wrong and are corrected here.**

1. **"~25% of alert volume is lost under `drop`" — not on this dataset.** It
   is **2.0%** on cptc-2017. The 25% figure is across all three datasets
   combined and is dominated by ccdc (1.05M of the 1.43M records) and by the
   single NETGEAR signature at 374k. Drop-vs-catchall is therefore nearly a
   no-op here (6 episodes) and the axis may only matter on ccdc. Re-measure
   per dataset before quoting it.
2. **"The FlexFringe alphabet multiplies" — it shrinks.** 20 symbols under
   AIF, 16 under hybrid, 9 under tactic. Symbols are `mcat|mserv` pairs, and
   collapsing stage codes collapses pairs faster than technique granularity
   expands them. The predicted consequence (sparser transitions, more sinks)
   should therefore go the other way, and the 38%-of-steps-via-sinks baseline
   may *improve* rather than degrade.

**The real effect is episode merging, and it is large.** Comparing AIF with
hybrid + catchall — which process the *identical* 43,299 alerts — episodes
fall **7,370 -> 4,608 (-37%)** and subsequences **2,339 -> 1,354 (-42%)**.
This is not alert loss; it is the taxonomy assigning one code where AIF
assigned several, so adjacent alerts merge into a single episode and fewer
severity drops occur to cut subsequences on.

That is the granularity/readability trade-off of 8a.5, quantified: fewer and
larger episodes and fewer attack attempts means a **better alert-compression
ratio** (the metric that operationalises analyst workload) bought with
**coarser structure**. Which way that reads depends on the graph metrics,
which need FlexFringe.

**Objectives are closer than the theory suggested.** AIF exercises only 4 of
its 13 possible objectives on this dataset, against hybrid's 3 and tactic's 1
— so the practical gap is 4-vs-3, not 13-vs-1. The tactic arm's collapse to a
single `impact` objective remains the sharper difference.

## 22. Task 4 — AIF vs ATT&CK attack graphs, measured on cptc-2017

First end-to-end run of the substitution. Three arms at commit `06cafbc`,
same pinned IANA snapshot, `PYTHONHASHSEED=0`, isolated run-roots, held-out
perplexity on seed 42. Everything is held constant except annotation
granularity:

| arm | annotation | objectives |
|---|---|---:|
| `aif` | `MicroAttackStage` (baseline) | 25 observed |
| `mitre_hybrid_catchall` | technique at medium/high, tactic at low | 5 |
| `mitre_tactic_catchall` | tactic throughout | 4 |

**Precondition established first.** `evaluation check` on the AIF arm against
`baseline/metrics-cptc-2017.json`: **18/18 structural metrics match**. Only
throughput and wall-clock differ, both flagged informational (this machine is
faster). The seven pipeline edits the taxonomy switch required are therefore
behaviour-preserving for AIF, which is what makes the comparison attributable.
The 19th metric, held-out perplexity, is reported missing by `check` for a
harness reason rather than a regression: `--heldout` is honoured only by
`command_run`, never by `command_check`.

**Result.**

| metric | aif | hybrid | tactic |
|---|---:|---:|---:|
| attack graphs | 104 | 10 (−90%) | 9 (−91%) |
| victims with a graph | 36 | 7 (−81%) | 7 (−81%) |
| objectives | 25 | 5 | 4 |
| total nodes | 1,885 | 145 (−92%) | 135 (−93%) |
| total edges | 3,024 | 223 (−93%) | 198 (−94%) |
| alerts per AG | 460 | 4,788 (+940%) | 5,320 (+1056%) |
| perplexity (training) | 13.48 | 9.45 (−30%) | 9.94 (−26%) |
| perplexity (held-out) | 40.27 | 29.12 (−28%) | 33.42 (−17%) |
| wall clock | 269 s | 49 s (−82%) | 49 s (−82%) |

**Finding 1 — the compression gain is lost coverage, not aggregation.**
"+940% alerts per AG" reads as a tenfold workload reduction and is nothing of
the kind: **29 of 36 victims receive no attack graph at all**. The ratio
improved because its denominator collapsed. The same caveat applies to the
82% speedup — less work, not faster work. This matters beyond this experiment:
alert-compression ratio is the metric the proposal uses to operationalise
analyst workload, and it rewards coverage loss indistinguishably from genuine
aggregation. **It should never be reported without a coverage figure beside
it.**

**Finding 2 — perplexity genuinely improves, and is not confounded.** It is
measured over traces rather than graphs, so the coverage collapse does not
flatter it: −30% training, −28% held-out. A coarser alphabet (16 symbols vs
AIF's 20) makes sequences more predictable. This is the one axis on which the
ATT&CK arms are cleanly better.

**Finding 3 — granularity is second-order.** `hybrid` (5 objectives) and
`tactic` (4) differ by a few percent on every structural metric. The gap that
matters is AIF-vs-ATT&CK, not hybrid-vs-tactic.

**Two hypotheses tested and falsified, which is what makes the cause
attributable rather than assumed:**

*Severity tiering.* ATT&CK files command-and-control as an enabler while AIF
treats data delivery/exfiltration as terminal objectives, so the first build
lost every non-DoS objective. Promoting `command-and-control` to HIGH — which
the proposal's Severity Configuration section asks for, "preserve the original
implementation's behaviour" — raised high-severity signatures from 57 to 146
and objectives from 4 to 11. It gained **one graph and zero victims**. Not the
cause.

*The subsequence length floor.* `model_learning.py` discards subsequences
shorter than 3 episodes, and the ATT&CK arms lose a larger share to it (62%
vs AIF's 53%), so it looked like an amplifier. Parameterised as
`SAGE_MIN_SUBSEQ` (default 3, unchanged) and re-run at 2: every arm gained
~12% more graphs and **the relative gap moved 0.2 points** (−90.4% to
−90.6%). Not the cause either.

**What is left, and it is the real finding.** The coverage loss is intrinsic
to vocabulary coarseness at the tier where the data actually lives. Our
ATT&CK mapping is *coarser* than AIF on this dataset despite ATT&CK having
~600 techniques to AIF's ~30 stages — 16 trace symbols against AIF's 20 —
because the hybrid design collapses 18 low-tier techniques into 3 tactics
(`reconnaissance`/`discovery`/`resource-development`) while AIF distinguishes
seven scanning stages. Scanning dominates cptc-2017's alert volume, so
adjacent distinct actions merge into single episodes (7,370 -> 4,891, −34%),
which leaves genuinely fewer distinguishable attack steps and far fewer paths
reaching an objective. The chain compounds: **−34% episodes -> −44% usable
traces -> −90% attack graphs.**

SAGE's graph output is therefore *non-linearly* sensitive to annotation
granularity, and the low tier is where that sensitivity concentrates.

**Consequence for the next step.** The low-tier collapse was forced by the
digit-count severity encoding (9 single-digit codes, 18 low-tier techniques).
Testing granularity properly requires dropping that encoding for an explicit
severity table — the option set aside at effort 21 — so techniques survive at
every tier.
