# Tiered ATT&CK mapping: build + results

Branch `research/b2-mitre-eval`, subfolder of the existing
`experiments/mitre_mapping/` spike (see `../results.md` for the 7-method
embedding/k-NN/SMET comparison this supersedes as "method 8"). Implements
the tiered strategy in `strategy.md` (Tier 0 rule-metadata harvest -> Tier 1
STIX entity/alias lookup -> Tier 2 classifier trained on the harvested
corpus -> Tier 3 similarity fallback -> Tier 4 abstain) against the same
773-signature ground truth (`../ground_truth_signatures.csv`) used
throughout `../results.md`.

**Headline finding is not "here's a more accurate method" — it's that Tier
0's free, independently-sourced vendor labels disagree with SAGE's own
bridge-table ground truth on ~30% of the scoreable population, in one
consistent direction, with zero counterexamples.** That's a bigger and more
actionable result than any accuracy number below. See §2.

Environment note: run entirely on native Windows Python 3.13
(`scikit-learn`/`numpy` only, no `torch`), unlike the SMET leg of the parent
comparison which needed a Linux/WSL conda env — this pipeline has no
FlexFringe or SMET dependency, so it didn't need one.

---

## 1. Tier 0 — harvest ET Open's own MITRE metadata

Fetched the full ET Open ruleset (`emerging-all.rules`, 50,797 rules,
46MB, not committed — re-fetched by `tier0_build.py` from
`rules.emergingthreats.net`, same "large, re-downloadable" treatment as the
STIX bundle). **27,521 of 50,797 rules (54%) carry `mitre_technique_id`/
`mitre_tactic_id` metadata** — vendor-authored, not inferred.

Matched by exact `msg:` text against our 773 signatures:

| | count |
|---|---:|
| ET rules with mitre metadata (unique msg text) | 26,644 |
| **Exact-match hits on our 773 signatures** | **88 (11.4%)** |

Well below the strategy doc's cited "40-70%" — expected, because our 773
signatures mix ET-prefixed rules (which this ruleset can match at all) with
Snort3/Talos-style community rules (`BROWSER-CHROME`, `SERVER-MYSQL`,
`FILE-FLASH`, `GPL ...`) that ET Open doesn't cover, and many of the older
ET rules that DO match predate MITRE tagging. The 88 hits are still worth
having at effectively 100% *extraction* precision — the question is whether
they *agree* with our existing ground truth. They mostly don't (§2).

The other 26,556 tagged-but-non-overlapping messages become Tier 2's
training corpus (§3) — this is the "free labeled corpus" the strategy
describes, used at its full external scale rather than just the 88-row
overlap with our own 773.

Reproduce: `python tier0_build.py` (writes `et_labeled_corpus.csv`,
`tier0_hits.csv`).

---

## 2. The headline finding: Tier 0 disagrees with the bridge table, not randomly

Comparing all 88 Tier 0 hits against `../ground_truth_signatures.csv`'s
propagated labels (`tier0_diff_check.py`): **0 of 88 agree** (strict set
intersection between ET's tagged technique(s) and our GT's `gt_ids`). That's
not noise — it resolves into two dominant, one-directional patterns:

| GT stage -> GT technique | ET's real tag | count |
|---|---|---:|
| `DATA_DELIVERY` -> T1105 (Ingress Tool Transfer) | **T1190** (Exploit Public-Facing Application) | 36 |
| `ARBITRARY_CODE_EXE` -> T1203 (Exploitation for Client Execution) | **T1190** (Exploit Public-Facing Application) | 32 |

68 of 88 hits (77%) are one of these two patterns, **100% consistent in
direction, 0 exceptions**. The signatures involved are exactly what you'd
expect: `ET WEB_SPECIFIC_APPS ... SQL Injection`, `... Remote File
Inclusion`, `... Local File Inclusion` — server-side web-application
exploitation attempts. Real-world ATT&CK convention (independently, from the
rule authors, with no knowledge of SAGE's bridge table) tags every one of
these T1190. SAGE's own bridge table (`../B4_mitre_replacement_design.md`
§2, transcribed into `../bridge_table.py`) instead sends `ARBITRARY_CODE_EXE`
to T1203 (which is specifically about *client-side* exploitation — browser/
Office-document payloads, not server-side web app attacks) and
`DATA_DELIVERY` to T1105 (Ingress Tool Transfer — downloading a *second-stage
payload*, not the exploitation step itself).

**This isn't a small edge case.** `ARBITRARY_CODE_EXE` and `DATA_DELIVERY`
are the largest and third-largest `MicroAttackStage` categories in the
entire `technique_scoreable` ground truth:

| stage | n | % of 562 technique_scoreable |
|---|---:|---:|
| ARBITRARY_CODE_EXE | 102 | 18.1% |
| INFO_DISC | 85 | 15.1% |
| DATA_DELIVERY | 68 | 12.1% |
| ... | | |
| **ARBITRARY_CODE_EXE + DATA_DELIVERY** | **170** | **30.2%** |

Roughly **30% of the headline scoring denominator used throughout
`../results.md` is anchored to a bridge-table mapping that 68 independent,
vendor-authored samples contradict unanimously.** The smaller disagreements
in the table (`INFO_DISC` -> T1592/T1590 vs ET's T1082/T1083;
`COMMAND_AND_CONTROL`/`LATERAL_MOVEMENT` tactic-only rows vs ET's concrete
T1570) are lower-volume but point the same direction: real deployed rule
metadata tends to be more granular/execution-specific than the
`MicroAttackStage`-level bridge table.

**Recommendation, not yet applied:** re-derive the `ARBITRARY_CODE_EXE` and
`DATA_DELIVERY` entries in `../bridge_table.py` (likely both toward T1190,
possibly split by whether the signature is server-side-exploit-shaped vs.
genuine second-stage-payload-shaped), then re-run `../score.py` on the
existing methods 1-7 — several of those numbers are probably being
suppressed by exactly this ~30%-of-corpus mislabeling, not by the
embedding/k-NN methods' own weakness. This wasn't done here to keep this
subfolder additive (`../ground_truth_signatures.csv` untouched); it's the
single highest-leverage next step.

---

## 3. Tier 1 — STIX malware/tool alias lookup

Built an alias table from STIX `malware`/`tool` objects'
`name`+`x_mitre_aliases`, restricted to `uses`-relationship technique sets of
size <= 5 (a LOLBin-style object with a huge technique fan-out is a weak
signal even on an exact name match), alias length >= 5, and an explicit
stoplist for common-English-word aliases that surfaced during probing
(`ping`, `page`, `photo`, `chaos`, `calendar`, `cannon`, `medusa`, `flame`,
`cobra`, `havex` — all real ATT&CK software aliases that also happen to be
ordinary words or substrings of unrelated signature text, e.g. "Low Orbit
Ion **Cannon**" spuriously matching malware alias "Cannon"). Without that
filtering the naive version matched 30 signatures with visibly garbage
technique unions (up to 18 techniques per hit); filtered, it's:

**12 hits, all inspected and legitimate** — `sqlmap`/`havij` (SQLi tools ->
T1190), `nbtstat`/`netstat`/`ipconfig` (native Windows discovery commands as
ATT&CK "tool" objects -> T1016/T1049). High precision, narrow coverage by
construction (1.6% of the 773) — this tier is a scalpel, not a workhorse.

Reproduce: `python tier1_build.py` (writes `tier1_hits.csv`).

---

## 4. Tier 2 — classifier trained on the Tier 0 free corpus

Two TF-IDF representations (`char_wb` 3-5gram; `word` 1-2gram), each feeding
a `OneVsRestClassifier(LinearSVC(class_weight="balanced"))`, averaged
decision scores, trained on the 26,644-row ET-tagged corpus (independent of
our 773, so no circularity) — tactic classifier and technique classifier
built and cross-validated separately (`tier2_cv_report.md`, 5-fold):

| | classes | in-corpus micro-F1 (5-fold CV) |
|---|---:|---:|
| tactic classifier | 14 | 0.981 |
| technique classifier | 45 | 0.978 |

Both look excellent — **but this is in-domain CV on ET's own text
distribution**, the easy version of the problem. The number that matters is
generalization to our 773 differently-styled signatures, and there's a
structural ceiling before that's even measured: **ET's own tagging
vocabulary only covers 45 distinct top-level techniques** (no
sub-techniques at all), dominated by T1190 (6,172 rows), T1071 (6,103),
T1568 (5,911), T1189 (2,007), T1566 (1,465) — five techniques account for
over 80% of the training corpus. A signature whose true label falls outside
that 45-technique set cannot be predicted correctly by this tier by
construction, and the extreme class imbalance means "the classifier is
confident" and "the classifier defaulted to the majority class" are hard to
tell apart from the decision score alone (see §6).

Reproduce: `python tier2_classifier.py` (writes `tier2_predictions.csv`,
`tier2_cv_report.md`).

---

## 5. Tier 3 — similarity fallback

TF-IDF (word 1-2gram) cosine similarity between the signature text and a
corpus built from each technique's name + description + `x_mitre_detection`,
over the **full** 697-technique live corpus (not Tier 2's 45-technique
vocabulary) — deliberately the same family of approach as methods 1-4 in
`../results.md` (embedding/TF-IDF similarity against technique
descriptions), included as a last-resort net with top-5 candidates, not a
claimed-accurate tier.

Reproduce: `python tier3_similarity.py` (writes `tier3_predictions.csv`,
top-5 per signature).

---

## 6. Combined pipeline: coverage and scored accuracy

`run_tiered.py` applies tiers in priority order (Tier 0 exact match > Tier 1
alias match > Tier 2 if top decision score > 0 > Tier 3 if cosine >= 0.05 >
Tier 4 abstain):

| tier | resolved | % of 773 |
|---|---:|---:|
| 0 (rule metadata) | 88 | 11.4% |
| 1 (alias lookup) | 10 | 1.3% |
| 2 (classifier) | 408 | 52.8% |
| 3 (similarity fallback) | 261 | 33.8% |
| 4 (abstain) | 6 | 0.8% |
| **coverage** (tiers 0-3) | **767** | **99.2%** |

Coverage looks great. **Scored accuracy against `../ground_truth_signatures.csv`
does not** (`score_tiered.py` -> `tiered_scores.json`):

| | top-1 (scoreable) | top-1 lenient | top-3 (scoreable) | right-tactic (scoreable) |
|---|---:|---:|---:|---:|
| **Tiered pipeline (all tiers)** | **2.1%** | 2.5% | 4.3% | 4.8% |
| Tier 0 only (n=81 scoreable) | 0.0% | 0.0% | n/a | 1.2% |
| Tier 1 only (n=5 scoreable) | 0.0% | 0.0% | n/a | 20.0% |
| Tier 2 only (n=334 scoreable) | 1.3% | 1.3% | n/a | 4.6% |
| Tier 3 only (n=139 scoreable) | 3.6% | 4.7% | n/a | 12.5% |

For comparison, `../results.md` methods 1-4 (embedding/TF-IDF similarity)
scored 5.5-8.4% top-1 on the same denominator. **This tiered pipeline scores
worse**, and the reason is diagnosable, not mysterious: Tier 2's top
predicted technique is **T1190 in 378 of 562 scoreable rows (67%)** — a hub
collapse driven by T1190 being both the training corpus's largest class
(§4) and, per §2, the class real vendor metadata says is actually *correct*
for the ARBITRARY_CODE_EXE/DATA_DELIVERY signatures that dominate this
corpus. Scored against the existing ground truth, that reads as "catastrophic
over-prediction of one class." Scored against Tier 0's independent
vendor-label evidence, the same behavior reads as "correctly generalizing a
real pattern that the ground truth itself encodes wrong for ~30% of the
corpus." Both readings are consistent with the data; **§2 is why this
matters more than the accuracy row.**

The Tier 2 "confidence" gate (`LinearSVC` decision score > 0 admits a
prediction) is also demonstrably too permissive under this much class
imbalance — a decision score can cross zero on the dominant class from
weak, generic lexical overlap alone. A tighter or margin-relative threshold
would shrink Tier 2's 52.8% coverage in exchange for fewer confident-looking
wrong answers; not tuned further here since §2 already explains most of the
gap between "looks wrong" and "is wrong."

Reproduce: `python run_tiered.py` then `python score_tiered.py`.

---

## 7. Honest limitations (matching `../results.md`'s standard, not relaxing it)

- **Ground-truth-quality confound dominates the accuracy numbers in §6.**
  Any tier's score against `../ground_truth_signatures.csv` is only as
  trustworthy as that ground truth, and §2 shows ~30% of the
  `technique_scoreable` population is anchored to a bridge-table mapping
  that independent evidence disputes. Until `../bridge_table.py` is
  corrected and re-propagated, accuracy comparisons between this pipeline
  and methods 1-7 (which share the same ground truth) are comparisons
  against a shared, partially-wrong yardstick — not proof either approach is
  better or worse at the underlying task.
- **Tier 0 coverage (11.4%) is far below the strategy doc's "40-70%"
  expectation**, because that estimate assumes a signature vocabulary
  dominated by the vendor rulesets it names (Sigma/Elastic/ET/Splunk); our
  773 signatures are a mix of ET and Snort3/Talos-style community rules, and
  ET Open alone can only ever match the ET-prefixed subset.
- **Tier 1 coverage (1.3%) is real but narrow by design** — the precision
  filtering that makes it trustworthy (length >= 5, technique-fan-out cap,
  explicit stoplist) also caps how much of the corpus it can ever touch;
  this is the strategy doc's own tradeoff ("very high precision... because
  malware/tool names are rare tokens" — true, but rare tokens are rare).
- **Tier 2's 45-technique training vocabulary is a hard ceiling**
  independent of the ground-truth-quality issue: even with perfect labels,
  no amount of tuning lets Tier 2 predict a technique outside ET's own
  45-technique tagging vocabulary.
- **Tier 3 is knowingly weak** (same family as methods 1-4, which scored
  5-8% top-1) — it's a coverage backstop, not a claimed-accurate tier.
- **One honest caveat carried over from the strategy doc itself:** some
  fraction of these 773 signatures are not really "one true technique"
  problems at all (SAGE's own `unmappable` partition, 89 signatures, exists
  for exactly this reason) — no tier here overrides that partition.

---

## Reproducing

```bash
# Tier 0: fetch ET Open ruleset, harvest metadata, exact-match against our 773
python tier0_build.py            # -> et_labeled_corpus.csv, tier0_hits.csv
python tier0_diff_check.py       # -> prints the Tier0-vs-GT disagreement table (section 2)

# Tier 1: STIX malware/tool alias lookup
python tier1_build.py            # -> tier1_hits.csv

# Tier 2: classifier trained on the Tier 0 free corpus (needs scikit-learn, numpy)
python tier2_classifier.py       # -> tier2_predictions.csv, tier2_cv_report.md

# Tier 3: TF-IDF similarity fallback over the full technique corpus
python tier3_similarity.py       # -> tier3_predictions.csv

# Combine tiers 0-4 in priority order
python run_tiered.py             # -> predictions_tiered.csv, unmapped.csv, provenance.csv

# Score against ../ground_truth_signatures.csv, overall + per-tier
python score_tiered.py           # -> tiered_scores.json
```

No production pipeline files touched. `emerging-all.rules` (46MB) is
git-ignored and re-fetched by `tier0_build.py`, same treatment as
`../enterprise-attack.json`.
