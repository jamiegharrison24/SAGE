# Replace-mode (rare-entity-only) — pre-registration

Written **before** the sweep was run, per the standing lesson that a 1-point
wobble reads as success when the success criterion is chosen afterwards.
Implements REPORT.md §8 item 7 — the one variant that tests effort 13's
original hypothesis.

## What is being tested

Effort 13 measured *augment* mode: `nmap` → `nmap <ENTITY>`. It was a negative
result (macro 22.2% → 19.4% / 21.3%). The report's own diagnosis of why:

```
augment   "nmap <entity> scan"  vs  "masscan <entity> sweep"   rare tokens STILL DIFFER
replace   "<entity> scan"       vs  "<entity> sweep"           now genuinely alike
```

Augment appends a near-constant and changes no distance. Only **replacement**
makes two rules alike. But unconditional replacement destroys `SQL` (DF 12.1%)
and `Injection Attempt` (DF 12.0%) — the tokens carrying the technique signal.
Hence: **replace rare spans only**, cut on measured corpus DF.

## Configuration, and why each value

| knob | value | why |
|---|---|---|
| merge rule | `gliner_only` | At 0.85 GLiNER is 73% strict with **zero** boundary/type errors (11 TP, 4 FP, 0 SPAN) — spans are either right or absent, the property replacement needs. NuNER wins rare recall but at 32% precision would replace `SQL` and `Injection Attempt`. |
| threshold | 0.85 | Pinned in the spans artifact; 73% per-entity precision vs 53% at 0.5. |
| rare cut | measured corpus DF | Not a hand-written protocol list — a hand list encodes the guess being tested. See `df_table.py`. |

Measured DF confirms the report's cited figures (`SQL` 12.06%, `Injection
Attempt` 12.02%, `URI` 0.62%, `UDN` 0.00%) — the DF table reproduces the
numbers §8 item 7 was written from.

**One measurement already contradicts the hand-list intuition:** `SMB` measures
**0.15%** and `RDP` **0.77%**, i.e. *rare* in this corpus, despite both being
named as high-frequency protocol tokens to leave alone. A hand-written protocol
list would have protected them; the measured cut does not. This is the concrete
reason the report insisted on DF.

## Baseline — re-measured, not quoted

`validation_report.md` currently reads micro **36.6%** (132/361), macro
**22.2%** over 51 distinct true labels, entity tagging off. Effort 13's augment
arms were `gliner_only` 19.4% and intersection 21.3% against that 22.2%.

One caution that had to be checked rather than assumed: REPORT.md records a
`reviewer_verdict` scoring fix that moved numbers after effort 13, and warns
that earlier documents cite stale figures. Verified — the 31.3% in that passage
is the **T1190 modal-class share**, not the headline; macro 22.2% in
`validation_report.md` is post-fix and current.

Even so the band below is anchored to a **freshly run off arm**, not to the
quoted 22.2%: `NORMALIZER_VERSION` was bumped for this feature, so every
embedding cache key changed, and arm zero re-establishes the baseline under the
identical code path the treatment arms use. If the re-run off arm does not
reproduce 22.2%, that discrepancy is the finding and the sweep stops until it
is explained.

## Falsification — decided in advance

Replace-mode is declared a **success** only if macro accuracy **exceeds the
22.2% off-baseline by more than 1.0 point** (i.e. ≥ 23.2%) on the same
scoreable rows, at some cutoff in the sweep.

It is declared a **negative result** if:

- macro lands within ±1.0 point of 22.2% (noise — the hypothesis bought
  nothing), **or**
- macro lands below 21.2%, **or**
- the best arm beats baseline only at a cutoff so low that `n_replaced` is
  near zero (a no-op dressed as a win).

**Guard against a no-op arm.** `stats()` reports `replaced` / `kept_frequent`.
An arm replacing ~0 spans is the off-baseline with extra steps; an arm keeping
~0 is unconditional replacement, which the DF gate exists to prevent. Both are
reported, not silently averaged into the headline.

## Second dimension: what replaces a span (added after the DF design)

`<ENTITY>` is **not a reserved symbol to the classifier.** Measured, not
assumed: the word vectorizer is `TfidfVectorizer(analyzer="word", ...)` with
sklearn's default token pattern `\b\w\w+\b`, which strips non-word
characters — so `<entity>` tokenizes to the bare word **`entity`**, colliding
with real uses (corpus DF 0.072%; `identity` 0.129% reaches it through
`char_wb` `entit` n-grams). The older placeholders have the same defect:
`<CVE>` → `cve`, `<VERSION>` → `version`.

The collision is small. The **dilution** is the real cost: `gliner_only` fires
on ~42% of corpus rows, so `marker` injects one near-constant word token *and*
its char n-grams into ~42% of documents — near-zero IDF for itself while
shifting every genuine feature's relative weight. That is exactly the cost
`marker_rate.py` documents for near-constant markers.

So the substitution is swept rather than assumed:

| style | `nmap scan` becomes | hypothesis |
|---|---|---|
| `marker` | `<ENTITY> scan` | effort 13's convention, carried forward for continuity |
| `drop` | `scan` | in REPLACE mode the *removal* is the mechanism; the marker is dead weight |
| `sentinel` | `qqentqq scan` | separates "does a placeholder help?" from "does the placeholder collide?" |

`drop` is the prior favourite: replacement works by deleting the rare token
that spuriously distinguished two rules, and nothing in that mechanism needs a
token left behind.

## Sweep — factored, not crossed

5 cutoffs × 3 styles = 15 validate passes, which is not worth it. Factored:

1. **Arm zero** — entity tagging off. Already run: micro 36.6%, macro 22.2%,
   reproducing `validation_report.md` exactly under the bumped
   `NORMALIZER_VERSION`. The harness is sound.
2. **Pre-screen the cutoffs** with `cutoff_screen.py` (seconds, no validate
   pass). `gliner_only` spans are mostly rare by construction, so 0.005 and
   0.05 may replace nearly the same set — in which case the cutoffs are one
   arm and "no cutoff separates" is itself the finding.
3. **Cutoff sweep at style=`drop`** over whatever cutoffs survive step 2.
   Fixed at `drop` deliberately, not at the `marker` default: `marker` injects
   a near-constant token whose dilution *scales with how many spans were
   replaced*, so the cutoff's effect and the marker's cost would move together
   and could not be separated. `drop` adds nothing, so this step measures the
   DF gate alone.
4. **Style sweep at the winning cutoff only** — `marker` / `drop` / `sentinel`.

### Guards on the `drop` arm

`drop` can erase a text entirely: a title that *is* one entity (`Mimikatz`,
`Sipvicious`) is fully covered by its own span. An empty document raises
nothing — it is an all-zero TF-IDF row, so the SVM classifies from the origin
and kNN retrieves against a degenerate vector, and those rows still emit a
confident-looking prediction from no information. `replace_spans` therefore
floors the empty case back to the original text, and `cutoff_screen.py`
reports an `emptied` column so a `drop` arm silently falling back on many rows
is visible rather than inferred.

`sentinel` is measured collision-free: `qqentqq` has corpus DF **0.0** and
appears as a substring of no retained n-gram.

### What was considered and rejected

"Too generic" has a second reading — *typed* markers (`<TOOL>`, `<PRODUCT>`,
`<PROTOCOL>`) in place of one `<ENTITY>`. That is already settled against, and
not by this document: both the gazetteer and GLiNER mistype roughly 1 entity
in 5 (the gazetteer calls `fortios` a product, GLiNER calls `FortiOS` a
company), and a type that is wrong 20% of the time is worse than no type. It
was a deliberate decision on 2026-09-11 and the three styles above all keep
the marker generic. The dimension being swept is *whether a placeholder should
be left behind at all*, not what type it should carry.

Step 2 gates step 3, so the cost is set by how much the DF gate actually
separates rather than by the size of the grid.

## Prior

REPORT.md §6.1 and effort 14 concluded the binding constraint is **corpus
coverage, not representation**, and that coverage-first ordering supersedes the
entity plan. This is therefore expected to close out a hypothesis, not to move
the headline. Recorded so the expected outcome is on the record before the
numbers are.

---

## Outcome (appended after the sweep; the text above is unchanged)

**Negative, decisively. The pre-registered bar was macro ≥ 23.2%; every arm
landed at 16.4–18.3%.**

| arm | spans replaced | micro | macro | vs baseline |
|---|---:|---:|---:|---:|
| baseline (off) | — | 36.6% | **22.2%** | — |
| effort 13 augment | — | — | 19.4% | −2.8 |
| `drop` @ 0.005 | 25.7% | 33.8% | **17.2%** | −5.0 |
| `drop` @ 0.01 | 29.9% | 33.5% | **16.4%** | −5.8 |
| `drop` @ 0.02 | 32.7% | 33.5% | **16.4%** | −5.8 |
| `marker` @ 0.005 | 25.7% | 34.6% | **18.3%** | −3.9 |
| `sentinel` @ 0.005 | 25.7% | 33.0% | **17.2%** | −5.0 |

The guards all behaved: the control arm replaced nothing, `must-keep` was never
hit, `emptied` was 0 at every cutoff, and each arm keyed its own embedding
cache. So the result is the hypothesis failing, not the harness.

**What the pre-registration got right:** fixing the bar in advance. A 1.1-point
spread between styles would have been easy to narrate as a win for whichever
style came out ahead.

**What it got wrong:** the prediction that `drop` would be the strongest style.
`marker` placed first. The tokenization argument — that `<ENTITY>` erodes to
the bare word `entity` and dilutes ~42% of documents — is a correct statement
about the normaliser and a wrong prediction about accuracy. `drop` removes the
marker completely and still loses to keeping it.

**Where the real constraint sits:** unchanged. §6.1 and effort 14 said
coverage, not representation. This was a representation lever pulled harder,
and it moved the number down.
