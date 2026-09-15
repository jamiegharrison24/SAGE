# Step 2 trial: GLiNER on terse signature titles

> **The consolidated reference for this work is [`../../REPORT.md`](../../REPORT.md).**
> This file remains the detailed record for effort 13, Step 2; read the report first.

Step 2 of `../../entity_normalisation_plan.md`, trial phase only. Answers the
four questions the plan set **before** any integration. `normalize.py` is
untouched.

Model: `urchade/gliner_medium-v2.1` (apache-2.0 — v2/v2.1 only; `gliner_base`
and v0/v1 are cc-by-nc-4.0). CPU inference. Labels declared at inference:
*hacking tool, software product, network protocol, malware family, company*.

Baseline to beat, from Step 1: **53% precision at 72.5% coverage**.

## The four questions

**Q1 — does it fire at all on ~8-word shorthand? YES.**
23 of 30 randomly sampled titles (77%), 34 entities. This was the main risk —
every prose-trained model tried in this branch has underperformed on this
register — and it is retired. GLiNER fires.

**Q2 — multi-word entities? YES, and this is its clearest advantage.**
`Nmap Scripting Engine`, `SQL Server`, `Joomla 3.7.0`, `SSL VPN`,
`TFTP Server`, `EDGE OOB Access` are all recovered as single spans. Step 1's
token matching structurally cannot do this — it got only `nmap` from the first
of those.

**Q3 — false positives on ET category tokens? YES. FAIL.**
`ET SCAN` → *hacking tool* (0.635, 0.756) twice, `WEB_SERVER` → *software
product* (0.501). Exactly the failure the plan flagged: these look like
entities and are not. 3 of 18 false positives.

**Q4 — does "network protocol" catch SMB/DNS/RDP? YES, with noise.**
Correct and high-confidence: `HTTP` 0.987, `SMB` 0.984/0.978, `NTP` 0.980,
`RDP` 0.973, `UDP` 0.926, `NFS` 0.871, `SIP`, `NETBIOS`, `ftp`.
Wrong, and also high-confidence: `URI` 0.974/0.929, `UDN` 0.943, `URL` 0.937,
`inbound` 0.702. Misses `MS Remote Desktop` entirely.

## Precision, and the threshold lever

Hand-verdicted all 34 entities from the random sample (`trial_sample.csv`).

**At the default threshold 0.5: 16/34 = 47% precision — *worse* than Step 1's
dictionaries.** Taken at face value, GLiNER loses.

But confidence is informative here in a way corpus frequency was not in Step 1:

| threshold | kept | precision | true positives retained |
|---:|---:|---:|---:|
| 0.50 (default) | 34 | 47% | 100% |
| 0.70 | 25 | 56% | 88% |
| **0.80** | 17 | **71%** | 75% |
| **0.85** | 15 | **73%** | 69% |
| 0.95 | 8 | 88% | 44% |

At 0.85 it reaches **73% precision while keeping 69% of the true positives** —
comfortably past Step 1's 53%. This is the opposite of Step 1's negative
result, where no frequency threshold separated signal from noise. Here the
model's own score does separate them, imperfectly but usefully.

Residual errors at 0.85 are concentrated and diagnosable: `URI`, `URL`, `UDN`
typed as network protocols. A tiny type-specific stoplist would remove them,
though that must be derived from the label schema rather than from eval false
positives.

## Error breakdown (all 34, threshold 0.5)

| kind | count |
|---|---:|
| not an entity at all (`URI`, `URL`, `inbound`, `etc`, `passwd`, `pwd`, `CRLF Injection`) | 13 |
| ET category tokens (`ET SCAN`, `WEB_SERVER`) | 3 |
| span right, type wrong (`PHP` → protocol, `LibuPnP` → malware family) | 2 |

## Type assignment is unreliable — and it matters for the design

Spans are found more reliably than they are typed:

- `FortiOS` → **company** (it is a product)
- `Coldfusion` → **company** (product)
- `BIG-IP` → **network protocol** (product)
- `PHP` → **network protocol** (language/product)
- `LibuPnP` → **malware family** (library)

This bears directly on §3.1's augmentation design, which emits `<TYPE>`. A
mistyped tag is a wrong feature, not merely a missing one. Worth considering a
generic `<ENTITY>` tag instead of a typed one — it sidesteps every error in
this category, at the cost of the type signal. Not decided here.

## Complementarity with Step 1 — the important structural finding

The two methods fail on *different* rows:

| title | Step 1 dictionaries | GLiNER |
|---|---|---|
| `ET SCAN Nmap Scripting Engine ...` | `nmap` only | **`Nmap Scripting Engine`** (full span) |
| `ET SCAN Nessus User Agent` | **`Nessus`** (as service) | **(none)** |
| `ET EXPLOIT FortiOS SSL VPN ...` | `fortios` → product ✓ | `FortiOS` → company ✗, `SSL VPN` ✓ |
| `ET SCAN Modified Sipvicious ...` | `modified` (wrong) | (none) |
| `ET WEB_SERVER Coldfusion cfcexplorer ...` | `coldfusion` ✓ + 2 wrong | `Coldfusion`, `cfcexplorer` |

GLiNER misses entities the gazetteer catches (`Nessus`), and catches entities
the gazetteer structurally cannot (multi-word spans). Neither dominates.

This is direct evidence for the combination the §7 research said is standard
practice — **gazetteer as features into / alongside NER, not as a competing
predictor** — and it is why Step 1's revised conclusion (do not integrate the
dictionaries standalone) was the right call.

## Environment additions

`pip install gliner protobuf` (pulled `sentencepiece`). `torch`,
`transformers` and `sentence-transformers` were already present.
`protobuf` is required because GLiNER's DeBERTa-v3 tokenizer needs the
SentencePiece converter under transformers 5.x; without it loading fails with
a `tiktoken` error. Model cache ~500MB under the HuggingFace cache dir.

## Integration: corpus pass and merge-rule elimination (2026-09-11)

Full GLiNER pass over every text `canonicalize()` can see — 32,273 distinct
strings from the three corpora plus the 500 eval rows — via
`build_spans.py`:

```
26.1 min at 20.6 rows/s   (the trial's 9.9 rows/s underestimated batched throughput)
13,561 / 32,273 texts carry >= 1 entity   (42.0%)
14,675 entities total                      (1.08 per tagged text)
artifact: data/entity_spans.json.gz, 0.4 MB
```

`marker_rate.py` then eliminated three of the five merge rules **before any
`validate.py` run**, on a frequency argument rather than an accuracy one:

| rule | corpus rows tagged | markers/tagged | verdict |
|---|---|---|---|
| union | 28,957 (91.0%) | 1.87 | **near-constant** |
| gliner_primary | 28,957 (91.0%) | 1.88 | **near-constant** |
| gazetteer_only | 28,480 (89.5%) | 1.62 | **near-constant** |
| gliner_only | 13,383 (42.1%) | 1.08 | informative |
| intersection | 6,240 (19.6%) | 1.04 | informative |

A marker present in ~9 of 10 corpus rows has near-zero IDF, so it cannot
inform the TF-IDF classifier — while still perturbing every kNN embedding.
That is cost without signal, and it is decidable from frequency alone.

The noise check says the same thing from the other direction. Most-tagged
strings on the eval set:

```
union         command x38, trojan x31, microsoft x27, uri x18, tor x18, known x10, download x8
gliner_only   uri x18, tor x18, http x15, ftp x10, cisco x7, smb x7, snmp x5, ntp x5, icmp x4, ssh x4
intersection  http x15, ftp x10, cisco x7, smb x7, snmp x5, ntp x5, icmp x4, ssh x4, fortios x3, oracle x3
```

`union`'s top tags are generic English — `command`, `trojan`, `known`,
`download`. That arm was re-measuring Step 1's 53% precision, exactly as the
plan predicted when it declined to integrate the dictionaries standalone.

**A concern the coverage numbers hide.** The surviving arms tag almost entirely
*protocols* — `http`, `ftp`, `smb`, `ssh`, `udp`, `icmp`. Those are already
high-frequency tokens shared across the corpus, so marking them adds little the
model could not already see. The generalisation Step 2 was built for is on the
*rare* entities — `nmap` → `masscan`, `fortios` → `coldfusion` — and GLiNER at
threshold 0.85 largely is not firing there. `uri` x18 is also a plain false
positive: a generic noun, not a named entity. If the measured arms come back
flat, this is the first place to look, and the honest reading would be that the
threshold buys precision by discarding exactly the spans that carried the
value.

## Measured result: the mechanism does not work (2026-09-11)

Three `validate.py` runs, same 361 scoreable rows, Layer D off:

| arm | micro | macro | T1190 share | NER cache misses |
|---|---|---|---|---|
| baseline (off) | 36.6% (132/361) | **22.2%** | 31.3% | — |
| `gliner_only` | 35.5% (−1.1) | **19.4% (−2.8)** | 33.8% (+2.5) | 0 |
| `intersection` | 37.1% (+0.5) | **21.3% (−0.9)** | 33.2% (+1.9) | 0 |

**Validity checks, both passed before interpreting:**

* The baseline reproduced the pre-change headline *exactly* (132/361, 22.2%,
  31.3%). Separately, `canonicalize()` with the tagger disabled was diffed
  against the committed `normalize.py` over all 31,825 corpus strings: **0
  differ**. The change is a proven no-op when off.
* **0 NER cache misses** in both arms, with tagged-row rates matching
  `marker_rate.py` exactly (42.0%, 19.7%). Had the eval titles missed the
  artifact, queries would have gone untagged while corpus rows were tagged --
  a train/inference asymmetry that would have produced a fake negative.

**The §6 prediction (macro up, hub share stable-or-down) was wrong in both
metrics, in both arms.** `intersection`'s +0.5 micro is 2 rows out of 361,
inside noise (1 SE ~ 2.5pp), and it arrives *with* macro down and hub share up
-- the exact combination §6 pre-registered as "suspect modal collapse before
celebrating". It is not banked as a gain.

### Why: augmentation cannot deliver entity generalisation

The finding is not "NER does not help". It is structural, and it was
derivable before the 26-minute pass was spent:

```
augment   "nmap <entity> scan"  vs  "masscan <entity> sweep"   rare tokens STILL DIFFER
replace   "<entity> scan"       vs  "<entity> sweep"           now genuinely alike
```

The motivating argument was that `nmap` and `masscan` should look alike to the
model. Augmentation *preserves* the distinguishing token and adds a marker
present in 42% of rows -- low IDF, little information, applied near-uniformly
across the corpus. Adding a near-common token to most rows moves every row
slightly closer to every other, including toward the hub. That is exactly the
observed direction: **T1190 share up in both arms.**

Only *replacement* produces the generalisation. §3.1 chose augment-not-replace
on risk grounds (a wrong tag should cost one spurious token, not destroy the
word carrying the signal), and generic-not-typed was chosen to keep the type
error rate out of play. Each decision was defensible alone; **together they are
structurally incapable of the mechanism that justified the work.**

Supporting detail: `sigma` kNN accuracy fell 30.8% -> 17.1% under
`gliner_only`, and the pre-registered protocol-bias concern held -- the spans
GLiNER is confident about at 0.85 (`http`, `ftp`, `smb`, `ssh`) were already
high-frequency shared tokens, so the marker landed where it was least needed.

### What this does and does not rule out

Ruled out, on evidence: generic appended markers from GLiNER@0.85, under
every merge rule (three eliminated on frequency, two measured).

Not ruled out, and untested: **replacement** of rare entities only (leaving
high-frequency protocols alone), which is the only variant that implements the
original hypothesis; a lower threshold; NuNER Zero. None should be attempted
without first stating what would count as success, because the cheap
frequency diagnostic (`marker_rate.py`) can pre-screen any of them in seconds.

## Not done

- ~~**NuNER Zero**~~ and ~~**SecureBERT2.0-NER**~~ — both now run at span
  level; see [`comparison_findings.md`](comparison_findings.md). NuNER wins
  rare-entity recall at every DF cut and both thresholds, but is less precise
  at every threshold (32% vs 44% strict at 0.5) and carries an 8x corpus noise
  burden: strings it false-positives on appear in 19.4% of corpus rows against
  GLiNER's 2.5%, driven by `SQL` (DF 12.1%) and `Injection Attempt` (12.0%).
  SecureBERT's `System` type does cover software products — the recorded open
  question, answered yes — but 65% of its output lands in a catch-all
  `Indicator` class and it is closed as unusable on this register.
- **The protocol-frequency argument above does not survive measurement.**
  Corpus DF over all 31,825 rows: `HTTP` 12.3%, but `RDP` 0.77%, `SMB` 0.15%,
  `NTP` 0.009%, `NFS` 0.006%. The "already high-frequency tokens" claim was
  read off eval-set tag counts, not corpus DF. Effort 14's coverage
  explanation supersedes it either way.
- The precision figures quoted above (47% / 73%) could not be reproduced from
  `trial_sample.csv`, whose `verdict` column ships empty. A re-run and
  re-verdict reproduces them (15 kept at 73% at threshold 0.85); the verdicts
  are now written down in `verdicts.py`.
- **No integration.** `normalize.py` untouched; no pipeline measurement, and
  Step 0 still gates any accuracy claim.
- Threshold 0.85 is chosen from a 34-entity sample. Directional, not tight.
