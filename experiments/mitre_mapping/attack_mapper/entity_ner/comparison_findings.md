# NuNER Zero and SecureBERT2.0-NER: the two models effort 13 left unrun

> Detail record for the span-level comparison. The consolidated reference is
> [`../../REPORT.md`](../../REPORT.md); the effort-13 record is
> [`findings.md`](findings.md).

`findings.md` closed with three open items. Two were models —
`numind/NuNER_Zero` (the plan's co-primary, §5 line 320) and
`cisco-ai/SecureBERT2.0-NER` (scoped as a sanity check, §5 line 321). This
answers both **at span level only**. No corpus pass, no `validate.py` arm,
`normalize.py` untouched.

Scripts: `compare_ner.py` (runs the three models on one fixed sample),
`verdicts.py` (the verdicts, the scoring, and the corpus-DF measurement).

## Three things that had to be fixed before anything could be compared

**The effort-13 environment was gone.** `gliner` was not installed in any
interpreter on this machine (Windows 3.13, WSL Ubuntu system Python, the
`smet` conda env), no GLiNER checkpoint was in either HuggingFace cache, and
`data/entity_spans.json.gz` was absent — it is gitignored (`.gitignore:55`),
so the three `validation_report_entity_*.md` files are the only surviving
record of those arms. Citable; not re-runnable without a rebuild.

**Effort 13's precision numbers were not reproducible.** `trial_sample.csv`
ships 34 rows with an entirely empty `verdict` column — the hand verdicts
behind "47% at 0.5, 73% at 0.85" were never written back. So GLiNER was re-run
and re-verdicted here rather than cited. On the raw title it reproduces
exactly — 23/30 titles (77%), 34 entities, and **15 kept at 73% precision at
threshold 0.85**, the same counts findings.md reports. The verdicts below
therefore agree with the lost ones closely enough to compare against.

**The first pass measured the wrong string, and was discarded.**
`normalize.entity_key()` is `strip_vendor_prefix()`, and `canonicalize()`
strips the prefix *before* handing text to the tagger — `build_spans.py` and
`marker_rate.py` both key on it. So the **vendor** prefix — `ET `, `GPL `,
`ETPRO`, `OS-`, `INDICATOR-` — is gone before any model sees the string. The
**category** token is not: `strip_vendor_prefix` removes only the first match
and returns, so `ETPRO EXPLOIT Possible EDGE OOB Access` becomes
`EXPLOIT Possible EDGE OOB Access`, which is why `EXPLOIT` still appears in
the FP table below. Tagging raw titles credited both models with spans that
cannot occur (`ET DOS`, `ETPRO EXPLOIT`) and inflated NuNER's error count by
about a third. Everything
below is measured on `entity_key(title)`; the prefix was stripped from 30/30
sampled titles.

**These verdicts were assigned by Claude, not by a human auditor.** Effort 13
called its equivalent "hand-verdicted" and then lost them; these are written
down in `verdicts.py`, one commented line per judgement, so they can be argued
with. Spot-check before quoting.

## Scoring: three categories, and a measured rare/common split

Effort 13 scored binary and folded "span right, type wrong" into the false
positives. That loses the distinction the integration design turns on — a
generic `<ENTITY>` marker does not care about the type, so a mistype costs
nothing there, while a boundary that swallows `DOS` costs a spurious token.

| | meaning |
|---|---|
| **TP** | exact named entity, correct type |
| **SPAN** | real entity recovered, but type wrong or boundary off (`DOS LibuPnP`, `EDGE OOB`, `Powershell`→hacking tool) |
| **FP** | not an entity — category tokens (`SCAN`, `WEB_SERVER`, `TROJAN`), technique names (`Injection Attempt`, `Brute Force Attack`), generic nouns (`inbound`, `backdoor`, `Web Application`), fragments (`pwd`, `UDN`, `514`) |

**The gating column is rare-entity recall**, pre-registered before the sweep
was computed per findings.md's own instruction. Effort 13's post-mortem
predicted its null: the generalisation the work was for lives on *rare*
entities (`nmap`→`masscan`), and a model earns the 26-minute corpus pass only
by winning there.

**But rarity is measured here, not assumed — and the measurement overturned
the assumption it was meant to confirm.** Effort 13 argued the surviving spans
were "almost entirely protocols — `http`, `ftp`, `smb`, `ssh` — already
high-frequency tokens shared across the corpus". Document frequency over all
31,825 corpus rows says otherwise:

```
HTTP    12.286%       SMB      0.151%       SIP      0.025%
RDP      0.767%       UDP      0.148%       NTP      0.009%
                      IBM      0.035%       NFS      0.006%
```

**Only `HTTP` is actually high-frequency.** `SMB` is in 0.15% of rows, `NTP`
in 0.009%. Effort 13's frequency claim was read off *eval-set tag counts*
(`http x15, ftp x10, smb x7` out of 361), not corpus DF — which is the
quantity that governs IDF. So the "protocols add nothing" mechanism that
findings.md offered for its null is **not supported** by the corpus. (This
does not rescue the null; effort 14's coverage explanation still stands, and
supersedes both.)

## Headline

Same 30 scoreable eval titles (`trial.py` seed 11), tagged on
`entity_key(title)`, threshold 0.5. Rare = corpus DF < 1%.

| model | titles fired | entities | TP | SPAN | FP | strict | lenient | **rare TP** | common TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GLiNER medium v2.1 | 23/30 (77%) | 32 | 14 | 4 | 14 | **44%** | 56% | 13 | 1 |
| NuNER Zero | 28/30 (93%) | 60 | 19 | 10 | 31 | **32%** | 48% | **16** | 3 |

NuNER fires on nearly every title (28/30 against 23/30) and emits 60 spans to
GLiNER's 32 — nearly twice as many predictions, not twice the coverage. It is
less precise at every threshold, and its threshold is a much weaker lever:

| threshold | GLiNER strict | NuNER strict | GLiNER rare TP | NuNER rare TP |
|---:|---:|---:|---:|---:|
| 0.50 | 44% | 32% | 13 | 16 |
| 0.70 | 52% | 45% | 11 | 14 |
| 0.80 | 69% | 45% | 10 | 12 |
| **0.85** | **73%** | 43% | 10 | 11 |
| 0.95 | **88%** | 54% | 6 | 6 |

GLiNER's span scores separate signal from noise (44%→88%); NuNER's per-token
scores barely do (32%→54%).

**NuNER wins the gating column at every cut, at both thresholds** — the split
is not an artifact of where "rare" is drawn:

```
                  DF cut  0.01%   0.05%   0.10%   0.50%   1.00%   5.00%
  threshold 0.50  gliner      5       7       7      12      13      13
                  nuner       9      11      11      15      16      18
  threshold 0.85  gliner      4       4       4       9      10      10
                  nuner       5       6       6      10      11      11
```

The entities it adds are exactly the register the gazetteer and GLiNER both
miss — `ASA 5500 Series Adaptive Security Appliance` (DF 0.000%), `NBSS`
(0.000%), `Linux Kernel` (0.000%), `Tivoli Endpoint` (0.000%), `AskMe`
(0.003%), plus `SpamAssassin`, `SMBLoris`, `Wscript` as SPAN-level hits. The
multi-word advantage the plan predicted for a token classifier is real.

## The finding that decides it: noise burden, 2.5% vs 19.4%

Rare recall is the gate, but it is not free. The question `marker_rate.py`
exists to ask is what share of corpus rows a rule tags. Measuring corpus DF of
each model's **false positive** strings:

| model | FPs | distinct | corpus rows containing ≥1 FP string |
|---|---:|---:|---:|
| GLiNER | 14 | 12 | **781 / 31,825 = 2.5%** |
| NuNER | 31 | 26 | **6,184 / 31,825 = 19.4%** |

**An 8× difference, and the cause is not what I expected.** Ruleset category
tokens survive stripping (`DOS`, `SCAN`, `TROJAN`, `WEB_SERVER`) but are
individually rare — `DOS` 0.02%, `SCAN` 0.16% — so they are *not* the problem.
The burden is generic technique vocabulary:

```
SQL                12.06%   NEAR-CONSTANT
Injection Attempt  12.02%   NEAR-CONSTANT
Remote              2.61%
EXPLOIT             2.58%
```

`SQL` and `Injection Attempt` alone are near-constant by
`marker_rate.py`'s own 85% / near-zero-IDF logic applied at the string level.
GLiNER's worst FP is `Inbound` at 0.96%.

This class is **not closed or enumerable** the way ET's category grammar is,
so it cannot be stoplisted without deriving the list from eval false positives
— the exact move findings.md ruled out for the `URI`/`URL`/`UDN` stoplist.

**This reverses the recommendation I would have made from recall alone.**

## SecureBERT2.0-NER — sanity check, question answered, closed

Not an arm; the plan scoped it as "wrong schema, prose-only per its own card".
Run once on the same 30 titles.

A config correction worth recording: under `aggregation_strategy="simple"` it
returns **subword fragments** — `'PL'`, `'OIT'`, `'IC'`, `'wd'` — because it
assigns *different* labels to adjacent subwords of one word, which blocks
grouping. That is a real instability signal, but scoring it that way measures
the config. Under `"first"` (the fair word-level read) it returns 95
whole-word entities over 30 titles.

**The recorded open question — does its `System` type cover software
products? — is YES.** 14 System spans including `MS`, `FreeBSD`,
`IBM Tivoli Endpoint`, `SQL Server Version`, `LINUX Linux Kernel`, `EDGE`,
`Remote Desktop Administrator`, `Cisco ASA 5500 Series Adaptive Security
Appliance…`.

**And it does not matter, because the schema is unusable here.** 95 entities
on 30 titles — 3.2 per title against GLiNER's 1.1:

| label | count |
|---|---:|
| Indicator | 62 |
| System | 14 |
| Malware | 9 |
| Vulnerability | 9 |
| Organization | 1 |

**65% lands in the catch-all `Indicator`**, 20 of 95 spans are ruleset
category tokens, and `System` itself contains `DOS`, `POLICY` and `Exploit`.
The prose-register mismatch the plan predicted on paper is confirmed in
measurement. **Closed — do not build on it.**

## Verdict against the pre-registered gate

**NuNER passes the gate on recall and fails on cost. No model swap earns the
corpus pass.**

- NuNER wins rare-entity recall robustly — at every DF cut, at both
  thresholds, by 2–6 entities on 30 titles. Directional, not significant, but
  consistent.
- It pays for it with 8× the corpus noise burden, including two genuinely
  near-constant FP strings. Under the existing *augmentation* design that is
  cost without signal, which is the same argument that eliminated three merge
  rules before any `validate.py` run.
- Under *replacement* it is worse, not better. §3.1 chose augment-not-replace
  precisely so "a wrong tag costs one spurious token rather than destroying
  the word carrying the signal" — and NuNER at 32% strict precision would
  replace `SQL` and `Injection Attempt`, destroying the tokens that carry the
  technique signal on ~12% of the corpus each.
- SecureBERT is closed.

None of this changes effort 14's conclusion. REPORT.md §6.1 lists entity
normalisation among the representation levers that all returned null for one
reason — coverage. `T1595.002` has 44 eval rows and 8 corpus rows; no NER
fixes that, and nothing measured here suggests otherwise.

## Addendum (2026-09-18) — a fourth, non-generic model, per supervisor direction

The three models above are all **zero-shot or fixed-schema-but-not-domain-trained**
(GLiNER/NuNER: generic zero-shot span/token classifiers, given cyber labels at
inference time; SecureBERT2.0-NER: cyber-domain-*pretrained* but its NER head
is a 5-class schema that collapses 65% of output into a catch-all `Indicator`).
Per explicit supervisor instruction, this section evaluates a NER model that is
both cyber-domain-**trained** and carries a schema with enough entity classes
not to collapse: `attack-vector/SecureModernBERT-NER`
(`ModernBERT-large`, fine-tuned on 502,726 hand-labelled spans across 22 types
— `THREAT-ACTOR`, `MALWARE`, `TOOL`, `PRODUCT`, `CVE`, `ORG`, `PLATFORM`,
hash/IP/domain types, `MITRE-TACTIC`, etc. — from threat reports, advisories
and incident writeups). Same harness (`compare_ner.py --models
securemodernbert`, `aggregation_strategy="first"` per the SecureBERT
`run_securebert` precedent), same 30-title sample (`trial.py` seed 11), same
`entity_key()`-stripped text, same TP/SPAN/FP rubric, same pre-registered gate
(`comparison_findings.md`'s "Verdict against the pre-registered gate" above:
rare-entity recall as the gate, corpus-DF noise burden of FP strings as the
cost). Verdicts are in `verdicts.py["securemodernbert"]`, assigned by Claude
per the same caveat as the other two arms — spot-check before quoting.

**Result: this is the first model in this branch to clear the gate on both
axes at once.**

| model | strict | lenient | rare TP (DF<1%) | common TP | noise burden (FP strings, corpus DF union) |
|---|---:|---:|---:|---:|---:|
| GLiNER medium v2.1 | 44% | 56% | 13 | 1 | **2.45%** (12 FP strings / 781 rows) |
| NuNER Zero | 32% | 48% | **16** | 3 | 19.43% (26 FP strings / 6,184 rows) |
| **SecureModernBERT-NER** | **59%** | **69%** | **17** | 2 | **1.63%** (6 FP strings / 519 rows) |

It beats GLiNER outright on every column (strict, lenient, rare TP, noise
burden) and beats NuNER on precision and noise burden while landing within one
rare TP of NuNER's raw count — and ahead of it once the DF cut is drawn
anywhere at or above 0.5% (gate-sensitivity table below). Its 6 FP strings are
almost entirely ET ruleset category tokens surviving `entity_key()` stripping
(`POLICY`×3, `SCAN`×2, `LINUX`×1) plus two genuine misses (`Lateral Movement`
— a MITRE tactic name used descriptively, not as a named entity; `Proxy`,
`Rapid` — generic nouns/adjectives in context). None of the near-constant
tokens that sank NuNER (`SQL` 12.06%, `Injection Attempt` 12.02%) appear in
its FP set at all — the 22-way schema does not reach for generic technique
vocabulary the way a coarser or more permissive model does.

**Gate sensitivity (rare TP count vs. where the DF cut is drawn), all three models:**

```
  at model threshold 0.50
     DF cut    0.01%    0.05%    0.10%    0.50%    1.00%    5.00%
             gliner        5        7        7       12       13       13
              nuner        9       11       11       15       16       18
   securemodernbert       10       11       12       13       15       17
```

SecureModernBERT-NER leads NuNER at every DF cut shown, including the
tightest (0.01%, essentially DF=0: 10 vs. 9), and leads GLiNER at every cut.
Unlike NuNER, this recall does not cost 8x the noise — the model's per-type
schema apparently lets it decline to fire on the generic technique-description
vocabulary that made NuNER's recall expensive.

**Two real, measured weaknesses, both worth recording rather than glossing over:**

1. **Boundary/type slippage on compound vendor+product names**, the same
   failure class GLiNER showed on `FortiOS`→company: `IBM Tivoli Endpoint`
   splits into `IBM`→ORG (correct) + `Tivoli`→TOOL (SPAN — the real product is
   "Tivoli Endpoint" or "IBM Tivoli", and TOOL is the wrong type for an IBM
   product line). `DOS Cisco 514 UDP flood` types `Cisco`→PRODUCT (SPAN —
   Cisco is the vendor, not a product) where the ASA-5500 title two rows later
   gets `Cisco`→ORG right. Type assignment is per-mention, not per-string —
   the same instability findings.md flagged for GLiNER's `FortiOS`.
2. **`MITRE-TACTIC` fires on tactic names used as descriptive English inside a
   rule title** (`Likely Lateral Movement`, both occurrences), not as a named
   reference to the ATT&CK tactic. This is structurally the same failure as
   scoring `CRLF Injection`/`Injection Attempt` as entities under the other
   models' schemas — a technique/tactic description is not a named entity —
   except here the model's own label vocabulary (`MITRE-TACTIC`) makes it look
   like a legitimate hit at a glance. Worth flagging for anyone re-verdicting
   this arm: don't credit `MITRE-TACTIC` spans without checking whether the
   text is *naming* a tactic reference or just *describing behaviour* in
   English that happens to match a tactic name.

**This does not change effort 14's conclusion, and the reasoning is the same
as for the other three models.** A model that recovers more/cleaner spans on
titles is still a *representation* lever; effort 14's diagnosis is that the
binding constraint is *corpus coverage* — `T1595.002` has 44 eval rows and 8
corpus rows, and no NER model, however well it tags, creates training examples
where there are none. This result changes only the answer to "does a
cyber-domain-trained model with a fine-grained schema out-measure zero-shot
generic NER on this register" (yes, decisively, on a 30-title sample) — not
the answer to "does entity work move the pipeline's score" (still gated by
Step 0/coverage, still unmeasured past span level, and effort 13's own
integration experiment already showed augmentation cannot deliver the
generalisation even when spans are good).

**What would justify spending the 26-minute corpus pass on this model,
specifically:** per the pre-registered gate this is now the strongest
candidate of the three to actually integrate — it is the first arm that does
not force the augment-vs-noise tradeoff NuNER did. The untested variant
`replace_prereg.md` flagged (replacement of rare entities only) was pointed at
GLiNER-at-0.85 *because* NuNER's noise burden ruled it out; this result
reopens that choice. Nothing here has been run past span level: no
`build_spans.py` pass, no `marker_rate.py` frequency check, no
`validate.py` arm. Per REPORT.md's own instruction, pre-register the success
criterion (mid/tail bucket accuracy, not micro) before spending it, and run
`marker_rate.py`-equivalent frequency screening first — it has caught three
merge rules as unusable, in seconds, before every prior expensive pass.

## Robustness check (2026-09-18) — n=100, independent draw

The addendum above ran on the same 30-title sample as the original three-model
comparison — small enough that "first model to clear the gate" could be a
lucky draw. Re-ran all three models together on a fresh, larger,
independently-seeded sample: `compare_ner.py --models
gliner,nuner,securemodernbert --sample 100 --seed 42` (100 titles vs. the
original 30, no overlap in the random draw's seed). All 437 resulting
entities hand-verdicted against the same TP/SPAN/FP rubric
(`entity_ner/verdicts_n100.py`).

**A bug worth recording, because it inverted the finding before it was
caught.** `securemodernbert`'s span text carries a leading space from the
token classifier's slicing (`" Microsoft"`, not `"Microsoft"`); the DF lookup
table is keyed on `.strip()`'d strings. The first pass looked up unstripped
entity text, so every `securemodernbert` DF lookup silently missed and fell
back to the "common" default — producing a table that said this model's
recall was mostly *common* strings (54 common vs. 12 rare), the opposite of
the true result. Caught by spot-checking `df_table.py --show` against the
individual strings before trusting the aggregate, which is exactly the kind
of check this branch's negative results have been built on. Fixed by
stripping at the lookup site, not just when building the table's keys.

**Corrected result: the addendum's finding holds, and by a wider margin than
the 30-title sample showed.**

| model | strict | lenient | rare TP (of TP total) | noise burden |
|---|---:|---:|---:|---:|
| GLiNER | 50% | 68% | 52/60 | 18.34% (up from 2.45% at n=30) |
| NuNER Zero | 37% | 53% | 59/72 | 49.82% (up from 19.43% at n=30) |
| **SecureModernBERT-NER** | **55%** | **69%** | **66/66** | **10.99%** (up from 1.63% at n=30) |

SecureModernBERT-NER wins strict and lenient precision, wins rare-entity
recall at **every** DF cut (gate-sensitivity table below), and its noise
burden is still the lowest of the three by a wide margin — even though all
three models' noise burden rose sharply at scale (a fixed set of FP strings
hits a larger, more varied corpus sample harder; the *ranking* between models
is what's being tested here, not the absolute numbers, which were never going
to reproduce exactly at 3x the sample size). Every one of its 66 true
positives falls below the 1% rarity cutoff — not because the model is
constrained to rare entities, but because this register (terse ET/Suricata
titles) simply doesn't contain many *correctly-recognized* common-word
entities for it to find; the common tokens it does encounter (`Windows`,
`Microsoft`, `Apache`) are still individually under 1% corpus DF.

```
  DF cut    0.01%    0.05%    0.10%    0.50%    1.00%    5.00%
  gliner       23       37       38       49       52       53
  nuner        30       44       44       53       59       66
  securemodernbert 31   49       50       62       66       66
```

At every cut, SecureModernBERT-NER >= NuNER >= GLiNER. The ordering from the
30-title sample was not a fluke.

**What changed, and what didn't, going from 30 to 100 titles:** all three
models' noise burden rose (a larger sample of corpus rows has more chances to
contain any given FP string), and NuNER's rose fastest in relative terms —
its FP set includes `SQL`, `Injection Attempt`-style generic technique
vocabulary that is inherently a large share of *any* sample drawn from this
corpus. SecureModernBERT-NER's FP set is dominated by ET ruleset category
tokens (`SCAN`, `TOR`, `TROJAN`, `DOS`, `CHROME`, `APACHE`) rather than
technique vocabulary — a closed, enumerable set findings.md already flagged
as stoplist-able from the label schema rather than from eval errors, which is
the cheapest remaining lever if this model is integrated.

**This still does not change effort 14's conclusion** — see the addendum
above; the reasoning is identical and the sample-size increase doesn't touch
it. What it does establish is that the addendum's headline was not a
statistical accident: SecureModernBERT-NER is a genuine, reproducible
improvement over both prior candidates on span-level cyber NER for this
register, confirmed on two independent samples totaling 130 titles.

## Pipeline integration and `validate.py` result (2026-09-18) — the answer is null

Everything above is span-level measurement. This section is the actual
`validate.py` pass Jamie asked for: does swapping SecureModernBERT-NER in for
GLiNER move the pipeline's real MITRE-mapping accuracy.

**Integration.** `entity_tagger.py` gained a `ner_backend` registry
(`NER_BACKENDS`, `EntityTagger(ner_backend=...)`) so either model can back
`--entity-tagging`, each keyed to its own spans artifact
(`data/entity_spans.json.gz` for GLiNER, `data/entity_spans_smb.json.gz` for
SecureModernBERT-NER) so a build of one never collides with or silently
overwrites the other. `build_spans.py`, `marker_rate.py` and `validate.py`
all take `--backend`/`--ner-backend`. Default backend is still `gliner`, and
the full test suite (23/23) plus a byte-for-byte fingerprint check confirm
this is a no-op for every existing arm. Full corpus pass:
`build_spans.py --backend securemodernbert` over all 32,273 texts
(corpus + eval), 29.9 min at 18.0 rows/s — tags **89.4%** of texts (vs.
GLiNER's 42.0%), consistent with the span-level finding that this model fires
far more readily than GLiNER.

**Pre-screen (`marker_rate.py --backend securemodernbert`) eliminates four of
five merge rules before spending a `validate.py` pass, on the same frequency
argument effort 13 used for GLiNER** — a marker present in ~9 of 10 rows has
near-zero IDF and is cost without signal for the TF-IDF classifier:

| rule | corpus rows tagged | verdict |
|---|---:|---|
| union | 97.5% | near-constant |
| gliner_primary | 97.5% | near-constant |
| gazetteer_only | 89.5% | near-constant |
| securemodernbert-only (`gliner_only`) | 89.5% | near-constant |
| **intersection** | **28.9%** | **informative range** |

Only `intersection` (NER ∩ gazetteer) was worth running. Its noise check is
notably cleaner than GLiNER's equivalent — top tags are specific tool/vendor
names (`mysql`, `nmap`, `cisco`, `microsoft`, `powershell`, `coldfusion`,
`solarwinds`) rather than GLiNER's mix of category tokens and generic English.

**Result: no measurable improvement. Micro is identical to the off baseline
row-for-row; macro is within noise.**

| arm | micro | macro | T1190 share |
|---|---:|---:|---:|
| baseline (off) | 36.6% (132/361) | **22.2%** | 31.3% (113/361) |
| **+ SecureModernBERT-NER, intersection** | 36.6% (132/361) | **21.5%** | 31.6% (114/361) |
| (for reference) GLiNER, intersection (effort 13) | 37.1% (134/361) | 21.3% | 33.2% |

Not just close — **the exact same 132 rows are correct** as the untagged
baseline. The -0.7 macro delta is inside the noise band effort 15 established
(within ±1.0), and T1190 share is flat. Unlike GLiNER's intersection arm
(+0.5 micro / -0.9 macro, a genuine but small hub-collapse-flavoured shift),
this arm doesn't move any of the three headline numbers in either direction.

**This is exactly what effort 14 predicts, now confirmed for the strongest
NER candidate measured on this branch, not just GLiNER.** A better span
recognizer changes what gets marked in the text corpus rows already contain;
it cannot manufacture technique-labeled training examples for
`T1595.002`/`T1499`/`T1498` (44/32/12 eval rows against 8/9/10 corpus rows —
effort 14's smoking gun) or shrink the register mismatch between this
network-IDS eval set and the Windows/host and cloud/endpoint corpora that
carry its diversity. SecureModernBERT-NER decisively wins every span-level
metric measured against GLiNER and NuNER Zero — and it still cannot move the
pipeline, because the two are different problems. **Span quality was never
the bottleneck; corpus coverage is, and no NER model changes that.**

Kept in the codebase (off by default, `ner_backend="gliner"`), because the
integration machinery is reusable regardless of this result and the
span-level win is real and independently useful (e.g. for a future feature
that consumes entity types directly rather than through this pipeline's
TF-IDF/kNN layers). Not adopted as a pipeline change. Full report:
`validation_report_entity_intersection_securemodernbert.md`.

## If one expensive run is spent, spend it here

The untested variant remains **replacement of rare entities only, leaving
high-frequency ones alone** — but on **GLiNER at 0.85, not NuNER**, which is
the opposite of what the recall column alone would suggest:

- At 0.85 GLiNER is 73% strict with **zero SPAN-level errors** (11 TP, 4 FP,
  0 SPAN) — boundaries are either right or absent, which is exactly the
  property replacement needs.
- Its 10 rare TPs at that threshold are only one behind NuNER's 11.
- Its residual FPs are `URI`, `URL`, `UDN` — DF 0.62%, 0.25%, 0.00%. Low
  blast radius under replacement, and the class findings.md already flagged as
  stoplist-able from the *label schema* rather than from eval errors.
- Replace only entities below a measured DF cut (0.5% keeps 9 of the 10),
  leaving `HTTP` alone.

One scoring detail a reader should be able to check rather than take on
trust: the two models are verdicted differently on the same string in the same
titles — GLiNER's `Powershell`→*hacking tool* is SPAN (type wrong), NuNER's
`Powershell`→*software product* is TP. That is a real type disagreement, not a
thumb on the scale, and it is **moot under this design either way**:
`Powershell` has DF 1.071%, above every proposed cut, so it is never replaced
by either model. Both GLiNER `Powershell` rows also score below 0.85, so the
"zero SPAN errors at 0.85" claim above does not rest on the call.

Two remaining items from findings.md's original list are still untouched and
should stay on it: **a lower threshold** (this sweep only filters upward from
0.5, so sub-0.5 behaviour is unmeasured), and the corpus pass itself.

Pre-register before running, and **not on micro** — effort 14 established that
micro is dominated by three head classes. The number to move is mid/tail
bucket accuracy (currently 31.4% / 17.1%). `marker_rate.py` pre-screens the
whole thing in seconds before any 26-minute pass is spent.

## Environment

`pip install gliner protobuf` on Windows Python 3.13 (torch 2.14.0+cpu,
transformers 5.16.1, gliner 0.2.29). `protobuf` is required for the DeBERTa-v3
tokenizer under transformers 5.x, as findings.md records. NuNER Zero downloads
~1.1GB; SecureBERT2.0-NER ~600MB. All three run on CPU; the 30-title sample is
seconds per model.
