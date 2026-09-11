# Splunk security_content corpus: built, measured, not adopted

Second half of the corpus-diversity experiment begun in
`../elastic_corpus/findings.md`. Same hypothesis (broaden technique coverage
to break the T1190 hub collapse), same method, different source — and unlike
Elastic, **this one did not earn its place and is not loaded**.

The corpus and this builder are kept on disk so re-testing is a one-line
change to `../corpora.py`, not a re-derivation.

## Fetching

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections
```

Shallow/sparse clone, 2,169 `.yml` files. `security_content/` is gitignored.

## Schema

Splunk detections are YAML. Title is top-level `name`; ATT&CK IDs are a
top-level `mitre_attack_id` list.

**Verified, not assumed.** Splunk's older published schema nested this under
`tags:`, and that is what most external references still show. On the current
checkout it is top-level — confirmed by parsing a real file and dumping its
keys before writing the extractor. `build_corpus.py` reads top-level first and
falls back to `tags.mitre_attack_id` so both revisions work.

Granularity follows the author's tag as-written (`T1552.002`), matching Sigma's
convention. Elastic is the deliberate exception, for the reason documented in
its own findings.

`detections/deprecated/` and `status: deprecated` are skipped (3 rules).
`status: experimental` (120 rules) is kept — these carry real author-assigned
ATT&CK IDs, and this is training data, not a production ruleset.

## Build result

- **2,166 files parsed, 100%, 0 exceptions.**
- 26 parsed detections carry no `mitre_attack_id` and are dropped.
- **2,140 labeled rows**, `../data/splunk_labeled_corpus.csv`.
- 376 distinct techniques, top-5 share 15.1% — on paper, diversity as good as
  Elastic's.

## Measured effect — the reason it is not adopted

Measured as an increment on top of Elastic, since that is the decision actually
being made ("should this be added to the current best stack?").

| config | micro | macro | T1190 share (true 28.5%) |
|---|---:|---:|---:|
| baseline (ET+Sigma) | 38.8% | 21.1% | 33.5% |
| +Elastic | 38.8% | **22.2%** | 29.0% |
| +Elastic +Splunk | **39.3%** | 21.8% | 27.5% |

Splunk moves micro up 0.5 points — **2 rows out of 397**, on a set where only
208 of 500 rows carry an explicit reviewer verdict — while moving macro *down*
0.4. That is not a win; it is noise in the direction of the headline number and
a regression in the metric that actually tracks per-technique reasoning.

The per-corpus attribution settles it:

```
kNN retrieval pool by corpus: {'et': 1169, 'sigma': 535, 'splunk': 298, 'elastic': 288}
knn_corpus top-1 accuracy by winning corpus:
    et 14/55 = 25.5%,  sigma 8/41 = 19.5%,  elastic 5/33 = 15.2%,  splunk 0/20 = 0.0%
```

Splunk's rows are retrieved often enough to win 20 top-1 slots and get every
one of them wrong. **20 rows is a small sample** — 0% and 10% are not
distinguishable at that size, so read this as "no positive signal detected",
not as a precise 0%. What makes the decision is the combination: no positive
retrieval signal *and* a macro regression *and* Elastic's own contribution
falling (27.9% → 15.2%) as the two compete for the same top-k slots. Any one of
those alone would be weak evidence.

Where the +0.5 micro actually came from: the source breakdown moved from
`{knn_corpus: 258, tier2_combined: 193}` to `{knn_corpus: 229,
tier2_combined: 222}`. The extra classes make the classifier vote positive on
29 more rows, promoting them from the weaker retrieval layer to the stronger
classifier layer. That is a real effect, but it is the classifier improving
*despite* Splunk's retrieval quality, not because of it — and it did not
survive into macro.

## Why it failed where Elastic succeeded — a hypothesis, not a measurement

Both corpora are similarly diverse on paper (376 vs 444 techniques, ~15% top-5
share each), so diversity alone clearly does not predict usefulness. That much
is measured. The *explanation* below is a post-hoc reading of rule-name style
and was not tested:

Splunk detection names tend to describe an analytic over a data model ("Detect
Certify Command Line Arguments", "Windows Registry Modification via Reg.exe"),
naming tooling and telemetry rather than observed behaviour. Elastic's tend to
name the event itself ("FortiGate Configuration File Downloaded"), which is
closer in register to a network IDS signature. Since retrieval matches on
surface wording, a register mismatch would explain the result — but confirming
it would need a measurement this experiment did not make (e.g. mean nearest-
neighbour similarity per corpus against the eval set).

The defensible generalisation is the weaker one: a corpus's own diversity stats
do not predict whether it will help. Check `neighbour_source_counts` and
per-corpus top-1 accuracy after adding it, before adopting it.

## Re-enabling

Add the path back to `CORPUS_PATHS` in `../corpora.py`. Worth revisiting if the
evaluation set ever broadens beyond network IDS signatures to host/EDR
telemetry, where Splunk's register would match rather than clash.
