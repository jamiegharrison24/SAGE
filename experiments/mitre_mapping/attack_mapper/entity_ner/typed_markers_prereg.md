# Typed markers (effort 17) — pre-registration

Written **before** the `validate.py` sweep is run, per the standing lesson
(`replace_prereg.md` carries the same header) that a 1-point wobble reads as
success when the success criterion is chosen afterwards.

## What is being tested

Every marker on this branch so far — GLiNER's, the gazetteer's, and
SecureModernBERT-NER's (`entity_ner/comparison_findings.md`'s addendum) — has
been the same generic `<ENTITY>` regardless of what type the source model
assigned. That was a deliberate 2026-09-11 decision
(`replace_prereg.md`, "What was considered and rejected"), reasoned from
GLiNER/the gazetteer's ~20% type-mistake rate (`fortios` tagged a product,
`FortiOS` tagged a company) — **never measured**, and never revisited for
SecureModernBERT specifically, whose fixed 22-label schema is the reason it
clears the pre-registered gate at all.

This tests whether a per-type sentinel (`qqe_productqq`, `qqe_orgqq`, ...
instead of one `<ENTITY>`) does better than the generic marker, using
SecureModernBERT-NER only — not a reopening of the GLiNER/gazetteer decision,
which per `comparison_findings.md`'s "Two real, measured weaknesses" section
still applies to SecureModernBERT too (`Cisco` → PRODUCT in one title, → ORG
two rows later; `IBM Tivoli Endpoint` splits ORG + TOOL). So this is
genuinely uncertain either way, not a foregone win.

## Configuration, and why each value

| knob | value | why |
|---|---|---|
| backend | `securemodernbert` | The only backend whose artifact stores per-span types (`build_spans.py`'s `has_types`); GLiNER is out of scope per the 2026-09-11 decision and current project direction. |
| merge rule | `intersection` | Matches the already-measured generic-marker pipeline result exactly (36.6%/21.5%, `comparison_findings.md`'s "Pipeline integration" section) — typing is then the ONE changed variable against a known number, not a new configuration measured for the first time. Also: every kept span under `intersection` IS an NER span (`merge_spans`'s `kept = [a for a in gl if ...]`), so there is no gazetteer-untyped-fallback ambiguity to worry about in this arm. |
| marker | `TYPE_MARKERS[etype]`, sentinel form (`qqe_<type>qq`) | Not literal `<TYPE>` — sklearn's `\w\w+` strips angle brackets (`MARKER`/`SENTINEL` already document this for the generic case), and a hyphenated type like `MITRE-TACTIC` would additionally split into two tokens. See `entity_tagger.py`'s `TYPE_MARKERS` comment. |
| gazetteer-only spans | `UNTYPED_TYPE` (generic fallback) | Moot for the `intersection` arm above; matters for a later `union`/`gliner_primary` arm if the per-type screen clears one. The gazetteer's own free-text type has never been measured for accuracy, so it is deliberately not surfaced even in typed mode. |

## Prior

REPORT.md §6.1 and effort 14 concluded the binding constraint is **corpus
coverage, not representation**. Typing a marker is still a representation
lever — it changes how a row is written, not whether the training corpus has
an example of the technique an eval row asks about. Effort 14 therefore
predicts null here too, same as it did for effort 16's generic-marker
`intersection` run this arm is a direct diff against. Recorded so the result
is readable either way.

## Success criterion — pre-registered before running

Per REPORT.md's own instruction (quoted in `comparison_findings.md`'s
"pipeline integration" section): **judge on mid/tail bucket accuracy, not
micro.** Micro is carried by three head classes (`T1190`/`T1071`/`T1568`) that
a marker's type can't help or hurt — those rows are already saturated with
training data (effort 14, bucket table: head 43.9% / mid 31.4% / tail 17.1%).
If typing does anything, the mechanism is disambiguating WHICH sparse-data
technique a rare, correctly-typed entity points to (e.g. a `PRODUCT` span
narrowing toward exploit/DoS-of-that-product techniques differently than a
`TOOL` span would) — that shows up in mid/tail, not head.

**Bar: mid or tail bucket accuracy moves by more than the ±1.0-point noise
band** already established for macro on this branch (effort 12's Elastic
result was read against that same band). A micro/macro change alone, with
bucket accuracy flat, is the same "same 132 rows, no signal" null effort 16
already recorded for the generic marker — not a new result.

## Before spending the pass

1. **Per-type frequency screen** (`marker_rate.py --backend securemodernbert
   --per-type`) — cheap, seconds, and is the check that could kill this arm
   outright if `PRODUCT`/`ORG` (the types `intersection` skews toward, since
   the gazetteer is vendor/product-heavy) turn out near-constant on their own
   even though no *merged* marker was.
2. Full corpus build (`build_spans.py --backend securemodernbert`) — does not
   exist locally as of this writing; the committed one lives on another
   machine and `.gitignore`s the artifact. ~30 min recorded elsewhere; this
   machine's `torch` build is CPU-only despite an available GPU, so budget
   more.

---

## Outcome (append after the sweep; the text above is unchanged)

**Negative. Bar not cleared in any way distinguishable from noise.**

Per-type screen (`marker_rate.py --backend securemodernbert --per-type`)
cleared first: no type is near-constant on the corpus (top: `DOMAIN` 44.9%)
or the eval set (top: `PRODUCT` 24.4%), confirming the mechanism the arm was
worth trying -- splitting one 89.4%-of-corpus generic marker across 22 types
does avoid the near-constant trap that ruled out `union`/`gliner_only`/
`gazetteer_only` generic. Worth a separate note: `DOMAIN` is the corpus's
top type (44.9%) but appears on only 0.3% of eval rows -- a register
mismatch consistent with effort 14's coverage diagnosis, not something this
arm can act on.

`validate.py --entity-tagging intersection --ner-backend securemodernbert
--typed-markers`, matched against the generic-marker run at the identical
configuration:

| | generic (effort 16) | typed | delta |
|---|---:|---:|---:|
| micro | 132/361 = 36.6% | 132/361 = 36.6% | **0** (same numerator) |
| macro | 21.5% | 20.5% | -1.0 pt |
| head (3 classes, 189 rows) | 45.5% | 46.0% | +0.5 pt |
| mid (21 classes, 137 rows) | 29.2% | 29.2% | **+0.0 pt** |
| tail (27 classes, 35 rows) | 17.1% | 14.3% | -2.9 pt |

Pre-registered bar was mid/tail moving beyond the ±1.0-point noise band.
Tail clears it numerically, but traced to its exact row
(`bucket_accuracy.py`'s diff): ONE signature (`ET EXPLOIT Possible GoldenPac
Priv Esc in-use`, true `T1068`) flips from a `knn_corpus` hit at confidence
**0.04** to a `knn_corpus` miss at confidence **0.03** -- both are
functionally a coin flip (this branch has repeatedly flagged sub-0.10
`knn_corpus` confidence as noise, e.g. the three-example walkthrough earlier
this session: 0.06, 0.28, 0.06 on unrelated rows). A 35-row bucket moves
2.9 points on a single flip, so the ±1.0-point band calibrated on macro's
361-row denominator does not transfer to it directly -- reading this as a
real regression would repeat effort 5's mistake (a conclusion drawn from
too small a sample). **Mid, the bucket with an actual sample size (137
rows), is dead flat at +0.0** -- the strongest evidence available that
typing produced no signal, positive or negative.

**Verdict: does not change effort 14's conclusion, same as effort 16's
generic-marker run it is a direct diff against.** The 2026-09-11 "generic,
not typed" decision is not reinstated by this result either -- it was never
in question for GLiNER/the gazetteer, and for SecureModernBERT the honest
finding is that typing is neutral (mid flat), not that it is actively worse
(tail's move is noise, not signal). The mechanism this arm hypothesized --
a correctly-typed rare entity disambiguating WHICH sparse-data technique a
retrieval lands on -- did not materialise, consistent with effort 14: the
type of a marker cannot manufacture a training example the corpus does not
have, so there was nothing for a more informative marker to disambiguate
*among*. Kept in the codebase (`entity_tagger.py`'s `typed_markers=True`,
`TYPE_MARKERS`), off by default, not adopted.
