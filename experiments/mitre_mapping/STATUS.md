# MITRE ATT&CK mapping research — status

Branch `research/b2-mitre-eval`. Standalone research spike under
`experiments/mitre_mapping/` — does not touch the production pipeline (see
repo `CLAUDE.md`). Goal: find a way to map SAGE's Suricata/ET signature
vocabulary to MITRE ATT&CK technique IDs that beats the current mapping
quality, and ideally generalizes beyond Suricata.

Five sub-experiments have run so far, in order. Each has its own detailed
write-up; this file is the index and the current bottom line.

## 1. Seven-method zero-shot/kNN/SMET comparison — `results.md`, `SMET_STATUS.md`

First spike. Built a 773-signature ground truth by propagating
`signatures/alert_signatures.py`'s `MicroAttackStage` labels through a
34-row bridge table (`bridge_table_validated.json`, validated with 0
problems against live STIX). Compared 7 methods against it:

| method | top-1 (scoreable) |
|---|---:|
| zero-shot embedding similarity, full technique list (ATTACK-BERT/MiniLM, 4 variants) | 5.5-8.4% |
| kNN (k=5) over the 773 labeled signatures | 56.6-61.0% *(inflated — see caveat below)* |
| SMET (external pretrained classifier, unblocked via a user-space Miniconda Python 3.9 env — see `SMET_STATUS.md`) | 13.2% |

**Caveat that matters:** the kNN numbers are not solving the same problem
as the rest. Because ground truth is *propagated from* `MicroAttackStage`,
kNN over the same 773 hand-labeled signatures mostly just re-derives the
original stage clustering wearing a technique-ID costume — it's not
evidence technique-level classification is "mostly solved." SMET is the
strongest genuinely-comparable zero-shot number, and it's still weak.

## 2. Tiered approach (Tier 0-4) — `tiered_approach/strategy.md`, `tier2_vs_audit_findings.md`, `embedding_swap_findings.md`

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

## 3. Generalisable HF-suggested pipeline — `hugging-face-suggestion/findings.md`

Implements the extract -> enrich -> narrate -> embed -> LLM-reason
architecture from a Hugging-Face-chat suggestion (`hugging-face-suggestion/
generalisable mitre mapper.md`), scoped to what this repo can actually
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

## 4. Sigma corpus pull — `sigma_corpus/findings.md`

Follow-on to effort 3's recommendation. Sparse/shallow-cloned SigmaHQ's
`rules/` (3,144 files, 18MB) and ran it through `hugging-face-suggestion`'s
`SigmaExtractor` for the first time against real (non-fixture) data —
**100% parsed, 0 exceptions.** 2,798 rules yielded a labeled
(rule -> ATT&CK technique) corpus, `sigma_labeled_corpus.csv`, built the
same way as the tiered-approach's `et_labeled_corpus.csv` so the two are
directly comparable:

| | ET corpus | Sigma corpus |
|---|---:|---:|
| rows | 26,644 | 2,798 |
| distinct techniques | 45 | 390 |
| top-5-techniques share | 81.3% | 22.8% |
| `T1203` training rows | 1 | 19 |

Confirms `embedding_swap_findings.md`'s prediction directly: Sigma covers
352 techniques the ET corpus never tags at all, and every ET technique that
had ≤1 training example gets ≥2 once combined.

Retrained Tier 2's exact classifier architecture on the concatenated
ET+Sigma corpus (`tiered_approach/tier2_classifier_combined.py`) and scored
it the same way: **38.0% top-1 (30/79)**, vs. 34.2% (27/79) ET-only — a real
but modest +3.8-point gain. The bigger effect is on hub-collapse, not raw
accuracy: top-1 `T1190` predictions drop from 76.8% to 52.5% of all matched
rows. Broadening the corpus is a genuine, evidence-backed lever, just not
individually a large one — see `sigma_corpus/findings.md` for the full
breakdown, including why this and effort 3's 48.8% are non-competing levers
(different signal sources) worth stacking rather than choosing between.

## 5. Stacking effort 3 + effort 4 — `hugging-face-suggestion/findings.md` ("Update" section)

The untried combination flagged above: `hugging-face-suggestion/attack_mapper/
classifier_resolver.py` wires effort 4's live-trained ET+Sigma classifier
into effort 3's pipeline as a new candidate source, slotted between the
high-precision IoC/bridge sources and the low-precision embedding fallback.
It only ever gets a turn on rows where `declared`/`ioc_alias`/`bridge_table`
found nothing (18 of 80 scoreable rows, pre-stacking) — i.e. exactly the
rows that used to fall through to the near-useless embedding layer.

**Result: 53.8% top-1 (43/80), up from 48.8%.** The classifier claims 5 of
those 18 rows (only when its own prediction clears a positive decision-
function score) and gets 4 right — 80% precision, though on a small enough
sample (5 rows) that this is suggestive, not a stable estimate. The other 13
still fall through to embedding, still at ~0% precision. Because the two
levers fire on disjoint rows by construction, the gain is strictly additive
— resolving the "do they add or overlap" open question from effort 4: they
add.

## Current bottom line

**53.8% top-1** (effort 5, stacking 3+4) is the best number across all
efforts, up from 48.8% (effort 3 alone) and 38.0% (effort 4 alone). The two
non-embedding, non-LLM levers identified so far — SAGE-internal signal
(declared tags + `MicroAttackStage` bridge) and a broadened training corpus
— compose cleanly because they resolve disjoint rows. Every embedding/
similarity-based method tried anywhere in this research branch (zero-shot
ATTACK-BERT/MiniLM, kNN, Tier 2 TF-IDF/MiniLM/ATTACK-BERT, Tier 2 combined,
Layer A in the HF pipeline) still tops out under 40% top-1 on independently-
reviewed rows on its own — every accuracy gain in this research branch has
come from a non-embedding signal.

## What's not done

- **Ground truth depth.** 100 hand-audited rows (80 scoreable), and their
  `reviewer_verdict`/`reviewer_notes` columns are still empty — these are
  proposed corrections from a prior analysis pass, not yet human-confirmed.
  The brief for the HF pipeline asked for 200+.
- **LLM reasoning layer.** Architecturally ready (`hugging-face-suggestion/
  attack_mapper/llm_client.py`) but has never actually run once, anywhere,
  in this research branch.
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
  results.md, SMET_STATUS.md          # effort 1: 7-method comparison
  bridge_table_validated.json         # MicroAttackStage -> ATT&CK, shared by efforts 1 & 3
  ground_truth_signatures.csv         # 773-signature GT, shared by efforts 1 & 2
  attack_data.py                      # shared STIX-bundle reader, shared by efforts 1 & 3
  tiered_approach/                    # effort 2: Tier 0-4
    strategy.md, results.md, embedding_swap_findings.md, tier2_vs_audit_findings.md
    emerging-all.rules                # vendored ET ruleset, reused by effort 3's Suricata extractor
    hand_audit_sample*.csv            # 100-row hand-audited sample, reused by effort 3
  hugging-face-suggestion/            # effort 3: generalisable pipeline; effort 5: stacked with effort 4
    plan.md, generalisable mitre mapper.md   # the original HF suggestion
    findings.md                       # effort 3's results + caveats + effort 5's "Update" section
    attack_mapper/                    # the implementation
      classifier_resolver.py          # effort 5: wires effort 4's classifier in as a candidate source
    validate.py, validation_report.md, tests/
  sigma_corpus/                       # effort 4: Sigma corpus pull
    findings.md
    build_corpus.py, sigma_labeled_corpus.csv, sigma_parse_failures.csv
    sigmahq/                          # third-party clone, not committed -- see findings.md to refetch
  tiered_approach/tier2_classifier_combined.py       # effort 4's retrained Tier 2
  tiered_approach/compare_combined_vs_audit.py       # effort 4's scoring
  tiered_approach/tier2_combined_vs_audit_findings.md
```
