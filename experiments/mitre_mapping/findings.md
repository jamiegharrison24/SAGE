# Implementing the HF-suggested generalisable mapper

`plan.md` / `generalisable mitre mapper.md` in this directory are a
Hugging-Face-chat suggestion for a format-agnostic, LLM-assisted pipeline
mapping *any* detection ruleset to MITRE ATT&CK (extract -> enrich -> narrate
-> embed -> LLM-reason -> score). This implements it, scoped per the user's
brief:

- extractors first, Sigma + the primary SIEM format (Suricata, since SAGE
  ingests Suricata alerts)
- IoC resolver built on internal threat intel, not a hand-typed lookup dict
- LLM swappable via a generic interface
- validation against a labeled test set
- a `MappedRule.processing_steps` audit trail

Code: `attack_mapper/`. Tests: `tests/test_extractors.py` (6/6 pass).
Validation harness: `validate.py` -> `validation_report.md`.

## Update: stacking in the ET+Sigma classifier (effort 4)

`STATUS.md` flagged this pipeline (effort 3) and the ET+Sigma-broadened
Tier 2 classifier (effort 4, `attack_mapper/sigma_corpus/findings.md`) as evaluated in
isolation but never combined. `attack_mapper/classifier_resolver.py` now
wires effort 4's classifier in as a candidate source, live-trained (not a
static lookup) so it resolves any rule text, not just the 773 signatures
already in `ground_truth_signatures.csv`. Placed between the high-precision
IoC/bridge sources and the low-precision embedding fallback — see
`reasoner.py`'s updated docstring for the exact ordering and why.

**Result: 53.8% top-1 (43/80), up from 48.8% (39/80).** Source breakdown
after stacking:

| source | hits / rows | accuracy |
|---|---:|---:|
| `declared` (Tier 0) | 9/11 | 81.8% |
| `bridge_table` | 30/60 | 50.0% |
| `tier2_combined` (new) | 4/5 | 80.0% |
| `embedding` | 0/3 | 0.0% |
| `ioc_alias` | 0/1 | 0.0% |

The classifier only ever gets a turn on rows where `declared`/`ioc_alias`/
`bridge_table` found nothing — 18 rows in the pre-stacking run, all of which
fell through to the near-useless embedding layer. Of those 18, the
classifier claims 5 (only when its own top prediction actually clears a
positive decision-function score — see `classifier_resolver.py`'s
docstring) and gets 4 right; the other 13 still fall through to embedding,
still at ~0% precision on this sample. Small sample (5 rows) — 80% here is
suggestive, not a stable estimate — but it moves net accuracy by 5 points
and does not touch the 71 rows other sources already answer correctly or
incorrectly, so it's a strictly additive change on top of the original
result, not a re-shuffle of it.

This confirms `STATUS.md`'s open question: the two levers add rather
than overlap, because they fire on disjoint rows by construction (the
combination only ever gets to act where SAGE's own internal signal has
nothing to say).

## Original headline result (pre-stacking)

**48.8% top-1 (39/80 scoreable) vs. the hand-audited sample
(`archive/tiered_approach/hand_audit_sample*.csv`), vs. 34.2% (27/79) for the
existing tiered-approach TF-IDF classifier
(`archive/tiered_approach/tier2_vs_audit_findings.md`).**

Read this number with the breakdown below, not instead of it — it is not an
apples-to-apples win over Tier 2. Kept for the record; superseded by the
53.8% above once the classifier was stacked in.

## Where the accuracy actually comes from

| source (top-1 mapping's origin) | hits / rows | accuracy |
|---|---:|---:|
| `declared` (ET's own `mitre_technique_id` metadata, Tier 0) | 9/11 | 81.8% |
| `bridge_table` (SAGE's `MicroAttackStage` -> ATT&CK bridge) | 30/60 | 50.0% |
| `embedding` (Layer A, zero-shot MiniLM similarity) | 0/8 | 0.0% |
| `ioc_alias` (Layer C, STIX tool/malware alias match) | 0/1 | 0.0% |

`declared` and `bridge_table` together cover 71/80 scoreable rows and
essentially the entire result. Two things follow:

1. **The embedding layer (Layer A) contributes nothing here**, confirming
   `archive/results.md`'s existing finding (zero-shot MiniLM/ATTACK-BERT
   similarity against the full technique list: 6.4-8.4% top-1 there, 0/8
   here). It is wired correctly (see "bugs fixed" below) and is genuinely
   useful as a low-confidence fallback for rules nothing else resolves, not
   as a real classifier.
2. **The LLM reasoning layer (Layer D) never ran.** No `openai`/`anthropic`
   package, no API key, no `.env` exists anywhere in this environment --
   `llm_client.NullLLMClient` is what `AttackMapperPipeline` uses by
   default, and `reasoner.py` logs `"llm_reasoning": "skipped"` in
   `processing_steps` on every row in this run. This 48.8% has **zero LLM
   involvement**, despite implementing "the LLM-suggested pipeline." The
   ABC (`llm_client.LLMClient`) and both provider adapters are written and
   ready; they are untested for lack of credentials.

So the actual lever behind the improvement over Tier 2 is not the
generalisable extraction/embedding/LLM architecture -- it's that this
pipeline has access to a piece of SAGE-internal context Tier 2's classifier
never saw at all: `signatures/alert_signatures.py`'s existing
`MicroAttackStage` label for the alert, fed through the already-validated
34-row bridge table (`attack_mapper/data/bridge_table_validated.json`, 0 validation problems
against live STIX -- `archive/results.md` section 1b). That's the "internal
threat intel" lever the user's brief called the highest-value
customization, and it is: reusing SAGE's own classification is a bigger
lever than better embeddings or a fancier candidate-fusion architecture,
which lines up with `archive/tiered_approach/embedding_swap_findings.md`'s
conclusion that embedding-model choice isn't the bottleneck for this
problem family.

## A circularity caveat, stated rather than resolved

`ground_truth_signatures.csv`'s `current_gt` column is *also* derived by
propagating `MicroAttackStage` through this same bridge table
(`archive/results.md` section 1c). So `bridge_table`-sourced predictions are, in
part, re-deriving the mechanism that produced the historical GT -- not
independent inference from rule content.

The scoring target used here is `proposed_technique`, not `current_gt` --
the auditor's independently reviewed correction, which disagrees with the
bridge-derived label in a majority of the miss rows (e.g. the Shellshock
Qmail/DNS signatures: stage `ARBITRARY_CODE_EXE` bridges to T1203, which the
auditor explicitly rejected in favor of T1190; `validation_report.md` has
more). So this is not pure circularity, but the 50.0% bridge_table figure is
better read as "how often SAGE's existing stage classification, at
signature granularity, still holds up under independent review" than as
evidence of new inference capability. Worth keeping in mind before treating
48.8% as a clean improvement number.

Even `declared` (ET's own official MITRE ATT&CK tags) isn't immune: 2 of 11
were rejected by the auditor (FortiOS SSL VPN CVE-2018-13379 tagged
`T1082`/Information Disclosure by ET, but the exploit itself is `T1190`;
Oracle JSF2 Path Traversal tagged `T1083`, auditor says `T1190`) -- vendor
metadata is high-precision, not perfect.

## Coverage caveat

The brief asks for a 200+-rule labeled regression set. This repo has 100
hand-audited rows (80 scoreable) across `hand_audit_sample*.csv` batches 1-3.
`validate.py` scores what exists and says so in its own output; treat 53.8%
as directional pending a larger audit batch, not as a satisfied validation
bar. The classifier-stacking result above is especially sensitive to this —
its own claimed rows are only a 5-row sample.

## What's implemented vs. what the HF sketch proposed

Built, adapted to this repo's actual context rather than transcribed
greenfield (the sketch was 30 files covering 6 rule formats + a from-scratch
IoC dict + a from-scratch STIX client):

- `models.py` -- `ExtractedRule`/`IoC`/`TechniqueMapping`/`BehavioralNarrative`/
  `MappedRule`, including `processing_steps` and a `micro_attack_stage`
  field the sketch didn't have (SAGE-specific input signal).
- `extractors/` -- `base.py` + `suricata.py` (primary format; handles both a
  full rule body and a bare signature-name string, the latter looked up
  against `data/emerging-all.rules` for the real body when possible, since
  rule bodies carry far more signal than titles per
  `archive/tiered_approach/strategy.md`) + `sigma.py` + a `generic.py` fallback.
  Not built: Splunk/KQL/Elastic/YARA extractors -- would be dead stub code
  today (no rules of those formats exist anywhere in this repo to test
  against), and CLAUDE.md rules out half-finished implementations.
- `mitre_client.py` -- thin wrapper over `attack_data.py` (reads
  `data/enterprise-attack.json`, no network fetch), both this package's own
  copies -- see "package promoted and made self-contained" below.
- `ioc_resolver.py` -- wraps `alias_table.py`'s STIX malware/tool alias
  table (with its hard-won stoplist for common-word alias collisions)
  instead of reimplementing a lookup dict, plus the `MicroAttackStage`
  bridge-table lookup described above.
- `narrative.py` -- template narrative generator (the actually-working
  default path), reusing `normalize.py`'s canonicalization rather than
  reimplementing it.
- `embedder.py` -- Layer A, MiniLM cosine similarity against every
  technique's name+description+detection text.
- `llm_client.py` -- `LLMClient` ABC, `NullLLMClient` (default, raises if
  ever called without being checked), `OpenAIClient`/`AnthropicClient`
  adapters (untested, no credentials available).
- `reasoner.py` -- priority-ordered candidate fusion (declared > ioc_alias/
  bridge_table > tier2_combined > embedding > optional LLM refinement) with
  a full evidence trail per candidate.
- `classifier_resolver.py` / `classifier_training.py` -- effort 5's stacked
  ET+Sigma classifier; see the "Update" section above.
- `pipeline.py` -- orchestrates all of the above into `MappedRule` +
  `processing_steps`.

## Update: package promoted and made self-contained

Originally built under `hugging-face-suggestion/` and reaching into
`tiered_approach/` for several runtime dependencies (the alias table,
`normalize.py`, the training corpora, `emerging-all.rules`,
`hand_audit_sample*.csv`). Per the user's explicit direction -- this is the
approach going forward, not one of several being compared -- the package is
now promoted to `experiments/mitre_mapping/attack_mapper/` directly, with
zero imports reaching outside its own tree:

- `attack_data.py`, `normalize.py` -- own copies (originals stay in
  `archive/` for that material's own scripts to keep working).
- `alias_table.py`, `classifier_training.py` -- own copies of just the
  reusable logic from `archive/tiered_approach/tier1_build.py` and
  `tier2_classifier.py` (their own script/CLI/CV-reporting code stays
  archived, since it isn't part of this package).
- `data/` -- own copies of `enterprise-attack.json`, `emerging-all.rules`
  (both gitignored, large), `bridge_table_validated.json`,
  `et_labeled_corpus.csv`, `hand_audit_sample*.csv`,
  `sigma_labeled_corpus.csv`/`sigma_parse_failures.csv`.
- `sigma_corpus/` -- folded in as a subfolder (`build_corpus.py` + its own
  `findings.md`), since it's this package's own data-pipeline step, not a
  separate experiment.
- Effort 1 (7-method comparison, `results.md`/`SMET_STATUS.md`/etc.) and
  effort 2 (`tiered_approach/`) moved to `archive/`, unmodified internally
  (their own cross-references to each other and to shared data files still
  resolve -- only this package stopped depending on them).

Re-ran `validate.py` after the move: identical 53.8% top-1 (43/80), same
source breakdown -- confirms the restructure changed only where files live,
not what the pipeline does. See `STATUS.md` for the full directory map.

## Bugs in the HF sketch, fixed here rather than transcribed

- `TechniqueEmbedder._precompute_techniques` was `pass`; `find_similar_
  techniques` then silently iterated an empty dict and returned `[]` --
  Layer A would have failed with no error. Fixed by actually embedding
  every technique on construction (`embedder.py`).
- `_generate_candidates` returned `list(candidates.values())`, dropping the
  `technique_id` keys the LLM prompt builder needed (every candidate would
  have rendered as `T????`). Candidates stay keyed by ID throughout
  `reasoner.py`.
- The same function did `candidates[tech_id]["sources"].append(...)` on a
  dict initialized with `"source"` (singular) -- `KeyError` on the first
  IoC/embedding overlap. Fixed with one consistent `evidence` list field.
- `core/config.py` used `Optional` without importing it. `config.py` here
  doesn't use `pydantic-settings` at all (not installed) -- plain
  `dataclass`.

## Reproducing

```bash
python -m pytest tests/test_extractors.py -v   # 6 extractor unit tests
python validate.py                              # -> validation_report.md
```

## Recommended next steps

1. Grow the hand-audit set toward 200+ rows before trusting any number here
   as a real regression baseline -- this is the harder, more valuable next
   step, not more pipeline engineering. Especially now: the classifier-
   stacking gain above rests on a 5-row sample.
2. ~~Pull SigmaHQ's ATT&CK-tagged rule corpus~~ -- done, see
   `attack_mapper/sigma_corpus/findings.md`.
3. ~~Stack effort 4's classifier into this pipeline~~ -- done, see "Update"
   section above.
4. Wire a real LLM client (`llm_client.OpenAIClient`/`AnthropicClient`) if
   credentials become available, and re-run `validate.py` -- Layer D is
   architecturally ready but has never actually executed.
