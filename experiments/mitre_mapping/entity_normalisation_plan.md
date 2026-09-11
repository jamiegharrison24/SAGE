# Entity-aware normalisation — plan and source of truth

Status: **planned, not started.** Nothing in this document is implemented.
Written before any code so the design, the decisions already settled, and the
measurements that would falsify it are all recorded in one place.

Supersedes nothing. Sits alongside `STATUS.md` (the effort index) and will
graduate into a numbered effort there once it is measured.

---

## 1. The problem this attacks

`STATUS.md` effort 12 left the bottom line at **38.8% micro / 22.2% macro**,
with `supervised_classifier` (43.1%) and `knn_corpus` (27.3%) answering 351 of 397
scoreable rows. Both read the same normalised text, produced by
`normalize.py:canonicalize()`.

That normaliser currently understands four entity classes, all regex:
`<CVE>`, `<IP>`, `<HEX>`, `<VERSION>`. It has no concept of a tool, a product,
or a protocol. Measured coverage over the 397 scoreable rows (model-free
count, 2026-09-11):

| entity class | rows | share | currently recognised? |
|---|---:|---:|---|
| STIX tool/malware alias | 10 | 2.5% | yes — `alias_table.py` |
| protocol token (`smb`, `dns`, `rdp`, …) | 87 | 21.9% | **no** |
| product/vendor token (`wordpress`, `jetty`, `fortios`, …) | 99 | 24.9% | **no** |
| **any of the three** | **178** | **44.8%** | 2.5% of it |

The STIX gazetteer reaches 10 rows, and `validation_report.md` shows
`ioc_alias` answering exactly 10 rows — so it is already extracting 100% of
what it can find. There is no tuning left in it. ATT&CK's STIX bundle models
malware and named tools; it has no object type for "SMB" or "WordPress", so
the gap from 2.5% to ~45% is **structural**, not a coverage bug.

Second measurement worth keeping: **313 of 841 candidate entity strings in the
eval set never appear anywhere in the 31,825-row training corpora.** Those rows
are ones `knn_corpus` structurally cannot help with — there is no neighbour to
retrieve for a tool the corpus has never seen. External resolution is the only
mechanism that can put information behind them.

**Coverage is a ceiling, not a benefit.** 44.8% of rows *containing* an entity
is the most this work could ever touch, not what it would gain.

## 2. The design

Entity-aware canonicalisation **inside `normalize.py`**, with every downstream
stage — classifier, kNN retrieval, reasoner, Layer D — left exactly as is.

### Why `normalize.py` and nowhere else

The earliest point in the pipeline is the extractor layer, but NER cannot live
there. The 31,825 training rows are plain CSV strings that never touch an
extractor; only the query does. Putting entity handling in extraction gives the
training side one text representation and the query side another — the precise
train/inference asymmetry this design exists to avoid.

`canonicalize()` is the only function both sides pass through, at four call
sites:

```
classifier_resolver.py:36   corpus      knn_resolver.py:64    corpus
classifier_resolver.py:92   query       knn_resolver.py:150   query
```

None of those four call sites change. The change is entirely inside
`canonicalize()`, plus one line in `knn_resolver.py` (see §4).

## 3. Decisions already settled

### 3.1 Augment, do not replace

`Nmap` → `nmap <TOOL>`, **not** `Nmap` → `<TOOL>`.

Full replacement collapses `Nmap`, `Amap` and `Mimikatz` into one identical
string. For our two consumers specifically:

- **TF-IDF + LinearSVC** — destroys the exact token whose IDF weight carries
  the discriminative signal, and the `char_wb` 3-5-gram vectoriser loses its
  substring evidence entirely.
- **MiniLM kNN** — makes distinct rules embed to near-identical vectors,
  directly amplifying the `T1190` hub collapse this project has fought since
  effort 8.

This mirrors de-identification practice, which moved from bare-tag replacement
to *surrogate generation* for the same downstream-utility reason.

The existing `<CVE>`/`<IP>`/`<HEX>`/`<VERSION>` placeholders stay full
replacement — there the specific value genuinely is noise. Tool identity is not.

### 3.2 Typing only — no entity linking

We want "Havij is a SQL injection tool", **not** "Havij → T1190".

Entities are features for normalisation, never answers. Two reasons: the
literature treats fine-grained typing as the separate, easier task (and
zero-shot NER removes the NIL problem for typing outright, since there is no
fixed KB to miss from); and a resolver that emits technique IDs would
reintroduce the circularity that `bridge_table` was removed for in effort 10.

This also means we skip the hardest and most error-prone stage of a standard
entity-linking pipeline.

### 3.3 Dictionaries first, NER second, web lookup last

Ordered by determinism, because every accuracy gain in this branch that
survived scrutiny came from structured signal and every model-inference layer
regressed or produced a fake win.

### 3.4 Dictionary matching policy — decided before building, 2026-09-11

Measured collision rates drove this. The three sources differ wildly in
quality, and **quality is inverse to size**:

| source | entries | generic-word collisions |
|---|---:|---|
| MISP `tool.json` | 620 | **zero** of 16 probe words — all real names (`LURK`, `Duqu`, `Zeus`) |
| IANA service names | 7,329 | ~20 of 48 probes (`who`, `auth`, `login`, `echo`, `time`, `daytime`, `talk`) alongside the genuinely wanted `http`/`smb`/`ssh`/`rdp` |
| CPE products | 63,577 | severe — 22 of 44 probes (`go`, `access`, `time`, `office`, `core`, `file`, `data`, `web`, `mail`, `user`, `server`) plus 804 junk entries ≤3 chars (`-`, `_`, `1.0`) |

A flat 63k match list is unusable, and `alias_table.py`'s hand-stoplist
approach does not scale from 212 entries to 63,577. Policy:

1. **Bound by our vocabulary, not theirs.** Only dictionary entries that
   actually occur as tokens in the corpus/eval vocabulary are considered. The
   problem size becomes our ~20k distinct tokens, not CPE's 63k products.
2. **Minimum length 4 characters**, must lead with a letter, reject pure
   numeric/version/punctuation forms.
3. **Generic-word stoplist** — sklearn's `ENGLISH_STOP_WORDS` plus a committed
   hand-written list of IDS/networking boilerplate (`server`, `client`,
   `file`, `data`, `web`, `access`, `service`, …). This is the known weak
   point; it is bounded (hundreds of words) where curating 63k is not.
4. **Per-source trust tiers** reflecting the measured quality above: MISP
   near-as-is, IANA restricted, CPE filtered hardest.

**What this policy cannot do**, and it matters: dictionaries answer "is this
string a known entity name", never "is this token an entity *in this
context*". `time` is a real IANA service and a real CPE product and almost
always an ordinary word in a signature title. Residual ambiguity is precisely
what §5 Step 2's NER exists to resolve — so Step 1's measured precision is
also the baseline Step 2 has to beat.

### 3.5 Any external resolution is offline, cached, committed and reviewed

Never a runtime web call. Rationale: a number that cannot be re-derived is not
a baseline, and this branch spent a week making its numbers trustworthy.
Caching also makes the result auditable.

**The documented failure mode to respect:** AVClass's automatic alias-update
module produced ~4,117 new alias pairs over 40M reports with significant error
— auto-generated gazetteers carry noise and entry conflicts, and a wrong
cached resolution becomes permanent and invisible. The literature's mitigation
is human review of the induced list. So the table must be *reviewable*, not
merely cached. (Same lesson as `reviewer_verdict`: an unreviewed label is a
hypothesis.)

## 4. Known traps

**The kNN embedding cache will silently serve stale vectors.**
`knn_resolver._corpus_fingerprint()` hashes corpus file path/size/mtime plus
`_MODEL_NAME`. Changing `canonicalize()` changes none of those, so the 49MB
`knn_corpus_embeddings.npz` is reused — corpus vectors built from old-style
normalised text, queries normalised new-style. Fails silently, with plausible
numbers. **Fix: hash a normaliser version string into the fingerprint and bump
it on every normalisation change.** One line, must land with the first change.
The classifier is unaffected — it refits from scratch each run.

**Scope is set by the corpus side, not the query side.** Because normalisation
must be symmetric, the lookup table has to cover entities appearing in the
corpus too. Upper-bound candidate counts (crude, no NER, inflated by ordinary
words and ET category labels):

| | distinct candidates | >2 occurrences | >5 |
|---|---:|---:|---:|
| eval set (500 signatures) | 841 | 169 | 68 |
| all corpora (31,825 rules) | 20,134 | 3,915 | 2,398 |

A frequency cap is what makes this tractable: resolving only entities seen more
than ~5 times takes the corpus-wide figure from 20,134 to 2,398.

**Register mismatch.** Every domain model tried in this branch underperformed
because they are trained on CTI prose and our text is ~8-word vendor shorthand.
Lower risk for NER than for sentence embeddings (`Nmap` is an easy span) but
not zero. Prior-art accuracy figures (AnnoCTR ~70% NER macro-F1, ~65% linking)
are measured on prose and must not be read as numbers we would inherit.

## 5. Sequencing

Each step independently measurable. Do not combine.

**Step 0 — unblock measurement. Convention now ruled on; implementation
pending.**

`reviewer_verdict` semantics, ruled by the project owner 2026-09-11:

| value | meaning | scoring |
|---|---|---|
| `1` | reviewer agrees with `proposed_technique` | **include** the row |
| `0` | reviewer disagrees | **exclude** the row from evaluation entirely |
| empty | not yet reviewed | unchanged — scored as today, flagged as unconfirmed |

`validate.py:190` currently treats *any* non-empty verdict as "confirmed", so
the 43 rejections are scored against the very label the reviewer rejected. 36
of them are scoreable and 22 are counted as HITs. Applying the rule above moves
the headline from **38.8% (154/397)** to **36.6% (132/361)**.

That drop is a measurement correction, not a regression — the same category as
effort 9's and effort 10's drops. Effort 12's Elastic result is unaffected: it
was measured as a delta across a constant evaluation set, so the bias sat on
both sides and cancelled.

Until this lands, a 1-2 point change from any work below cannot be
distinguished from the existing bias, so it gates everything else.

**Step 1 — deterministic dictionaries. DONE 2026-09-11, not integrated.**
See `attack_mapper/entity_dicts/findings.md`.

Built a 94,786-entry typed gazetteer (`data/entity_gazetteer.csv`) from the
three sources below. Measured on the 397 scoreable rows: **72.5% coverage at
~53% precision** (hand-checked 30-match sample); IANA-sourced matches 77%
precise, CPE-sourced 35%, MISP galaxy contributed 4 rows.

Two negative results worth carrying forward:

- **Corpus-frequency gating does not fix precision.** Tested against the 30
  labelled matches using training-corpus DF only: best 61% precision at the
  cost of 4 of 15 true positives. The distributions interleave because most
  false positives are *rare* words CPE lists as products (`retrieve`, `quad`,
  `trojan`). Rarity does not imply entity-hood.
- **The per-source precision gap is not a usable slicing rule.** Rendering
  real titles under each configuration shows good and bad matches mixed
  *within* both sources: a service-only configuration discards correct product
  tags (`fortios`, `coldfusion`, `microsoft`) while keeping wrong service tags
  (`traversal`, `quad`, `domain`), and is strictly worse than all-sources on
  some rows.

**Decision: do not integrate Step 1 standalone.** No dictionary-only
configuration is good enough, because the discriminator is whether a token
denotes an entity *in this title* — which nothing in Step 1 can see. The
gazetteer is carried into Step 2 as a feature/candidate source instead, which
is the standard practice the §7 research found anyway (gazetteer as features
into NER, not as a competing predictor). `normalize.py` remains untouched.

Step 1 therefore sets the bar Step 2 must beat: **53% precision at 72.5%
coverage**, and supplies evidence that a model is needed rather than a bigger
list.

Sources harvested:

| source | targets | licence | notes |
|---|---|---|---|
| NVD CPE dictionary | product/vendor (24.9%) | US-gov, not copyrighted | CPE 2.3 names carry `part` (a/o/h) + `vendor` + `product` as separate fields — a free type label. `tiiuae/cpedict` distils to a small daily-rebuilt CSV, Apache-2.0. |
| MISP galaxy `tool.json` | the tool class ATT&CK omits | **CC0** | explicitly covers "common software regularly used by adversaries" — the Nmap/Havij/Sipvicious class |
| IANA service-names/ports CSV | protocol/service (21.9%) | public | `sage.py` already downloads IANA port mappings |

Measure coverage against the 397 scoreable rows *before* integrating, the same
model-free way §1 was measured — subject to §3.4's matching policy.

**Report three numbers, not one.** §1's 44.8% came from a 90-word hand list
where every entry was genuinely a product or protocol. A 63k list will report
far higher coverage that is mostly noise, so bare match counts would lie:

1. rows matched at all,
2. rows matched by a **distinctive** token (post-§3.4 filtering),
3. **per-match precision on a hand-checked sample of ~30 matches.**

Without (3) a real gain cannot be told from a garbage one — the exact shape of
number this project has been burned by twice (effort 8's modal collapse,
effort 12's rejected-label inflation).

**Not gated by Step 0.** Coverage counting is not accuracy evaluation, so the
`reviewer_verdict` fix is irrelevant until integration. Step 1's numbers are
uncontaminated by it.

**Step 2 — NER for what dictionaries cannot do.** Span detection for entities
no dictionary lists, and context disambiguation — which retires
`alias_table.py`'s hand-built `ping`/`page`/`chaos` stoplist, the textbook
symptom of gazetteer-only matching.

**Model shortlist (researched 2026-09-11).** The decisive constraint is
*schema*, not accuracy: the security-specific models predict a fixed set
(Indicator / Malware / Organization / System / Vulnerability) with **no TOOL,
PROTOCOL or PRODUCT type** — exactly the classes that make up our headroom —
and a fixed-schema model cannot be asked for new types. Zero-shot models let
types be declared at inference, which is why they win here despite the
security models' better headline F1.

| model | licence | vetting | role |
|---|---|---|---|
| **GLiNER v2.1** (`urchade/gliner_medium-v2.1`) | apache-2.0 | ACL-cited, reference implementation, maintained | **primary** |
| **NuNER Zero** (`numind/NuNER_Zero`) | MIT | 14.5k downloads/mo, arXiv 2402.15343 | **swap-in comparison** — +3.1% token-F1 over GLiNER-large; token classifier, so better on multi-word spans |
| SecureBERT2.0-NER (`cisco-ai/`) | apache-2.0 | best-vetted of all (Cisco, arXiv 2510.00240) | one-off domain sanity check only — wrong schema, prose-only per its own card |
| CyNER 2.0, AITSecNER | MIT / unclear | single-author / Medium-published | rejected on the vetting bar |

**Licence trap:** `urchade/gliner_base` and all v0/v1 GLiNER checkpoints are
**cc-by-nc-4.0 (non-commercial)**. Only v2/v2.1 are apache-2.0. Pin
deliberately.

**Trial before integrating** — ~30 real eval titles, scoring four things:
1. Does it fire at all on 8-word shorthand? (the failure mode that has sunk
   every prose-trained model in this branch)
2. Multi-word tools — "Nmap Scripting Engine", "Grim's Ping".
3. **False positives on ET category tokens** — `WEB_SERVER`,
   `CURRENT_EVENTS`, `WEB_SPECIFIC_APPS` look like entities and are not.
   Because the table is committed, a false positive here is permanent and
   invisible — the AVClass failure mode in §3.4.
4. Does declaring "network protocol" actually catch SMB/DNS/RDP, or only
   tools?

Include `SecureBERT2.0-NER` in the trial rather than rejecting it on paper.
It is the best-vetted candidate, and the schema objection rests on an
untested assumption: its **System** type may in practice cover software
products (WordPress, Jetty, FortiOS), which is the 24.9% class. If it does,
the objection largely collapses and only the protocol class is unreachable
for it.

**Step 3 — external resolution for the residual tail.** Only entities surviving
steps 1 and 2. Offline, cached, committed, human-reviewed per §3.4.

## 6. Prediction

Recorded before implementation, per the practice that made effort 12
trustworthy. Mechanism is better entity coverage → less reliance on surface
wording → less hub collapse:

- **macro up**, **`T1190` share** (currently 29.0% against a 28.5% true base
  rate) stable or slightly down, **micro flat to slightly up**.
- If micro jumps several points while macro is flat, suspect leakage or modal
  collapse before celebrating.

Attribute with the per-source instrumentation added in effort 12
(`neighbour_source_counts`, top-1 accuracy split by winning corpus). A change
in the headline with no change in what gets retrieved is a reweighting
artifact, not new signal.

## 7. What is prior art and what is not

- **NIL detection / Entity Discovery and Linking** (TAC-KBP) — the established
  name for "recogniser finds a span, it is not in the KB, resolve it". NIL
  detection is normally a confidence threshold, not a separate model.
- **Zero-shot entity linking** (BLINK and successors) — entities represented by
  short textual *descriptions* rather than identifiers. Descriptions as the
  unit of transfer is mainstream, not an improvisation.
- **Gazetteer induction / bootstrapping** — the established name for the
  offline-resolve-and-persist pattern.
- **AnnoCTR** — links MALWARE and TOOL mentions to ATT&CK's `/software/`
  subtree; direct precedent for `alias_table.py`'s job.
- **AVClass / AVclass2 / ClarAVy** — offline deterministic alias normalisation;
  strongest methodological precedent, and the source of the §3.4 warning.
- **CTINexus** (Euro S&P 2025) — closest overall: coarse entity typing then
  similarity-based merging, but types entities *internally* rather than by
  external lookup. Effectively this design minus the lookup.

One research pass found **no published system doing live external lookup of
unknown security entities with caching**. Every component is standard; that
combination appears not to be. Treat as promising, not as a settled literature
review — it has not been verified against a systematic survey.

## 8. Sibling lever — modernising `supervised_classifier`

**Not part of this plan's sequence.** Recorded here because it is the other
candidate lever, because the two interact in a way that is easy to get wrong,
and because it must not be run in the same measurement as §5.

### What it is

`supervised_classifier` (renamed from `tier2_combined`, 2026-09-11) is dual
TF-IDF + OneVsRest LinearSVC. That is architecturally **rcATT** (2019), which
2024+ literature treats as the outdated baseline newer systems benchmark
against and beat. It answers 174 of 397 scoreable rows at 43.1% — the most
accurate of the sources that scale.

### The prior negative result, and why it is not the same test

Effort 2 (`archive/tiered_approach/embedding_swap_findings.md`) swapped
TF-IDF features for MiniLM and ATTACK-BERT embeddings feeding the same
LinearSVC: **29.1% / 30.4% against TF-IDF's 34.2%** — both worse.

That was **feature swapping**, not encoder adaptation. Frozen general-purpose
embeddings fed to a linear model never learn anything about this task or
vocabulary. Adapting the encoder itself has never been tried here. Any
modernisation attempt must be end-to-end to count as a genuinely new test,
otherwise it just re-runs a known failure.

### Options

| option | what it is | cost | why it is new |
|---|---|---|---|
| **SetFit** | contrastive sentence-transformer tuning, built for small/imbalanced data | CPU-viable | cheapest real test of encoder adaptation — **recommended first move** |
| **End-to-end fine-tune** | SecureBERT 2.0 / ModernBERT as a 521-class classifier over the 31,825 rows | realistically needs a GPU (free Colab/Kaggle tier suffices) | domain-pretrained encoder adapted to our labels; the approach TTPXHunter used |
| **Hierarchical labels** | predict tactic or parent technique first, then sub-technique | cheap, no new model | attacks hub collapse and the macro/micro gap directly rather than raw accuracy |

Note SecureBERT appears here as an **encoder to fine-tune**, which is a
different artifact from `cisco-ai/SecureBERT2.0-NER` (the token-classification
checkpoint rejected for NER in §5 Step 2 on schema grounds). Rejecting it for
NER does not reject it here.

### The interaction — do not assume the levers are additive

§5's normalisation is tuned for the *current* consumers: a bag-of-n-grams
TF-IDF model and MiniLM retrieval. Both are highly sensitive to surface
variation, which is why vendor-prefix stripping, entity placeholders and
abbreviation expansion help them.

A fine-tuned transformer is **not** the same consumer. Subword tokenisation
already absorbs much of that surface variation, and aggressive normalisation
may help less — or actively hurt, since `<TOOL>`-style tags are
out-of-vocabulary artifacts and stripping vendor prefixes discards information
a transformer could otherwise use. So "normalise first, then swap the
classifier" is **not** safe to assume: the right preprocessing depends on the
consumer, and the normalisation that helps TF-IDF may need to be dialled back
for a transformer.

Practical consequence: if both levers are pursued, the transformer must be
evaluated against **both** raw and normalised text before concluding anything.
Treat "which preprocessing suits which model" as an open question, not a
settled pipeline order.

Independent of all this: §5's normalisation still lifts `knn_corpus`
regardless of what happens to the classifier, since both read
`canonicalize()`. And a classifier swap changes only one of four sources —
`declared`, `ioc_alias` and `knn_corpus` are untouched either way.

## 9. Open questions — not decided

- ~~`reviewer_verdict` `0`/`1` semantics~~ — **ruled 2026-09-11**: `1` =
  agree/include, `0` = disagree/exclude from evaluation. See Step 0. Still to
  do: encode it in `validate.py` and in `label_queue/CONVENTION.md`, which
  documents the column as starting empty but never defines its values.
- 11 of the 43 rejected rows carry a correction in `reviewer_notes` as free
  text ("t1021.004 is correct, t1110 is not") that nothing parses. Under the
  rule above these rows are simply excluded, so that signal stays unused —
  worth revisiting only if the scoreable-row count gets tight.
- ~~Which NER model~~ — shortlisted 2026-09-11, see Step 2: GLiNER v2.1
  primary, NuNER Zero as swap-in comparison. Final pick still depends on the
  Step 1 result (if dictionaries capture most of the 44.8%, the marginal value
  of any model shrinks) and on the four-point trial.
- Whether to modernise `supervised_classifier` instead or as well — options
  and the interaction warning are now written up in §8. Still undecided:
  whether to pursue it at all, and if so whether before or after §5.
- Whether `SecureBERT2.0-NER`'s **System** entity type actually covers software
  products (WordPress, Jetty, FortiOS). §5 Step 2 rejected it on schema
  grounds, but that was reasoned rather than measured, and it is the
  best-vetted candidate on the list. Added to the Step 2 trial.
