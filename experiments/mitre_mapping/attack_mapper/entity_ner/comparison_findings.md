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
