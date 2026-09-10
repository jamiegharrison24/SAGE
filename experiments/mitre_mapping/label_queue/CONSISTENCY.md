# Re-label consistency check

A 500-row label set is only as good as its repeatability. This measures it,
so the number reported next to the set is honest rather than implied.

## Method

25 rows sampled from `attack_mapper/data/labeled_set_v2.csv`
(`random.seed(20260910)`, reproducible), stripped to bare signature strings in
`recheck_queue.csv`, and re-labeled by an **independent agent with no memory of
the first pass** — a fresh context, not a fork, specifically so it could not
recall the original answers. It received `CONVENTION.md` and the same blind
restrictions, and wrote `recheck_labeled.csv`.

## Result

| measure | agreement |
|---|---:|
| exact string match on `proposed_technique` | **22/25 = 88.0%** |
| technique-overlap (either label's technique set intersects) | **24/25 = 96.0%** |

## The three disagreements are one disagreement

| signature | pass 1 | pass 2 |
|---|---|---|
| `ET POLICY Executable and linking format (ELF) file` | `ambiguous: (none) / T1105` | `T1105` |
| `ET POLICY Executable served from Amazon S3` | `ambiguous: (none) / T1105` | `T1105` |
| `ET TROJAN Possible NanoCore C2 60B` | `TA0011` | `T1095` |

Two of the three are the same unresolved question: **is an `ET POLICY`
executable-download rule benign software distribution or tool ingress?**
`CONVENTION.md` says policy rules are generally `(none)`, and also says
malware/second-stage downloads are `T1105`; a rule matching an ordinary binary
transfer satisfies both. The third is the sibling question of whether to record
a tactic when a mechanism is nameable (pass 2 read the rule body's fixed 60-byte
raw-TCP beacon and chose `T1095`, which is the better-evidenced call).

So the residual disagreement is a **convention gap, not labeler noise** — and a
gap concentrated in `ET POLICY` download rules, which a reviewer can resolve
once and apply to every affected row.

## What this licenses

Labeling is repeatable at 88-96%. That is high enough that the gap between
53.8% (original 100 rows) and 34.1% (blind 400) **cannot be explained by
labeling drift**, which was the main competing hypothesis. See `../findings.md`
for what does explain it.

It does **not** make these labels ground truth. Repeatable and correct are
different properties: a systematic misreading of the convention would reproduce
faithfully across passes and still be wrong. `reviewer_verdict` stays empty
until a human confirms, and 96% is the ceiling on what this set can tell you,
not a claim about its accuracy.

## Reproducing

```bash
python -c "import csv,random; ..."   # see the seed above; queue is committed
# then re-run an independent labeling pass against recheck_queue.csv
```
