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

Six sub-experiments have run so far, in order. Each has its own detailed
write-up; this file is the index and the current bottom line.

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

## Current bottom line

**53.8% top-1** (effort 5, stacking 3+4) is still the best number and the
default. Non-embedding, non-LLM signal remains the only thing that has
actually helped in this branch: SAGE-internal signal (declared tags +
`MicroAttackStage` bridge) and a broadened training corpus compose cleanly
because they resolve disjoint rows. Every embedding/similarity-based method
tried anywhere in this research branch (zero-shot ATTACK-BERT/MiniLM, kNN,
Tier 2 TF-IDF/MiniLM/ATTACK-BERT, Tier 2 combined, Layer A in the HF
pipeline) tops out under 40% top-1 on its own — and now Layer D, the one
piece explicitly designed to add reasoning on top of everything else, has
made things *worse* (effort 6) in its only test so far. Every accuracy gain
in this research branch has come from harvesting or combining existing
structured signal, not from any model — embedding, classifier, or LLM —
reasoning freshly over rule text.

## What's not done

- **Ground truth depth.** 100 hand-audited rows (80 scoreable), and their
  `reviewer_verdict`/`reviewer_notes` columns are still empty — these are
  proposed corrections from a prior analysis pass, not yet human-confirmed.
  The brief for the HF pipeline asked for 200+. This is the one item that
  needs a human, not more engineering.
- **LLM reasoning layer needs a design fix, not just a bigger model.**
  Effort 6 tested it (`llama3.2:3b`) and got a 20-point regression, traced
  to `reasoner.py`'s full-override design (Layer D reprocesses every row,
  not just uncertain ones, and replaces rather than blends prior
  confidence). Two untried fixes before drawing a final conclusion: (a) gate
  Layer D to only fire on low-confidence/`embedding`-sourced rows and blend
  rather than replace confidence; (b) retry with `llama3.1:8b` or a hosted
  model once (a) is in, to separate "small local model" from "override
  design" as the cause. Neither attempted yet.
- **The classifier-stacking gain rests on a 5-row sample** (effort 5, the
  18 rows that used to fall through to embedding, of which the classifier
  claims 5). Directionally promising, not a stable estimate — the 200+-row
  ground-truth gap above is what would firm this up.
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
    mitre_client.py, ioc_resolver.py, narrative.py, embedder.py,
    llm_client.py, classifier_resolver.py, reasoner.py, pipeline.py
    extractors/                  # suricata.py (primary), sigma.py, generic.py, base.py
    data/                        # own copies of every data dependency:
      enterprise-attack.json      # gitignored, large -- STIX bundle cache
      emerging-all.rules          # gitignored, large -- vendored ET ruleset
      bridge_table_validated.json
      et_labeled_corpus.csv
      hand_audit_sample*.csv      # the 100-row hand-audited sample (effort 2's, reused)
      sigma_labeled_corpus.csv, sigma_parse_failures.csv
    sigma_corpus/                # effort 4: how the Sigma corpus was built
      build_corpus.py, findings.md
      sigmahq/                   # third-party clone, gitignored -- see findings.md to refetch

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
