# Does swapping Tier 2's features fix the T1190 hub-collapse?

> **The consolidated reference for this work is [`../../REPORT.md`](../../REPORT.md).**
> This file remains the detailed record for effort 2's encoder-swap null; read the report first.

Short answer: no. Three feature representations tested, all trained on the
same architecture (OneVsRestClassifier(LinearSVC), same 26,644-row
et_labeled_corpus.csv, same 773 target signatures), scored against the same
100-signature hand-audited sample (`hand_audit_sample*.csv`, 79 scoreable
rows -- see `tier2_vs_audit_findings.md` for the original TF-IDF result this
extends):

| features | top-1 vs hand-audit | T1190 top-1 rate | EDGE OOB case (should be T1203) |
|---|---:|---:|---|
| TF-IDF (char 3-5gram + word 1-2gram) | 34.2% (27/79) | 76.8% (76/99) | T1190 @ 0.9354 |
| MiniLM embeddings (all-MiniLM-L6-v2) | 29.1% (23/79) | 62.0% (49/79) | T1190 @ 0.6752 |
| ATTACK-BERT embeddings (basel/ATTACK-BERT, security-domain-tuned) | 30.4% (24/79) | 58.2% (46/79) | T1190 @ 1.2629 |

Hub-collapse rate drops somewhat with better embeddings (77% -> 58%), but
overall accuracy does not improve, and all three still confidently mis-call
the EDGE OOB browser-exploit signature as T1190 -- ATTACK-BERT does it with
*more* confidence than either generic model, despite being the one model
actually trained on security-domain text.

## Root cause: this was never a feature-representation problem

`et_labeled_corpus.csv`'s technique-label distribution, over all 26,644 rows:

| technique | rows | % of corpus |
|---|---:|---:|
| T1190 | 6,172 | 23.2% |
| T1071 | 6,103 | 22.9% |
| T1568 | 5,911 | 22.2% |
| T1189 | 2,007 | 7.5% |
| T1566 | 1,465 | 5.5% |
| **top 5 total** | **21,658** | **81.3%** |
| ... | | |
| T1203 (the EDGE OOB signature's correct label) | **1** | 0.004% |
| T1018, T1021, T1498, T1552, T1072, T1114, T1037, T1078 | 1-3 each | negligible |

No text encoder, however good, can teach a per-class linear classifier
anything from a single training example. The three-way comparison above
holds this constant (same corpus, same imbalance) and only varies the
feature representation -- and the result barely moves, because the
bottleneck is upstream of feature representation entirely.

## Implication

Further embedding-model swapping is not expected to help. The actual lever
is broadening/rebalancing the *training corpus's* technique coverage --
e.g. folding in Sigma's ATT&CK-tagged rules (different domain: host/EDR
telemetry rather than network IDS, but covers technique territory ET's
network-rule corpus barely touches, including client-side/host-based
techniques like T1203) -- rather than trying a fourth embedding model on
the same 45-technique, 5-technique-dominated corpus.

## Reproducing

```bash
python tier2_classifier_embed.py       # MiniLM variant -> tier2_embed_predictions.csv
python tier2_classifier_attackbert.py  # ATTACK-BERT variant -> tier2_attackbert_predictions.csv
# original TF-IDF variant: tier2_classifier.py -> tier2_predictions.csv
# corpus class-imbalance table above: see corpus_stats.py, or:
python -c "import csv,collections; c=collections.Counter(); [c.update(r['technique_ids'].split(';')) for r in csv.DictReader(open('et_labeled_corpus.csv',encoding='utf-8')) if r['technique_ids']]; print(c.most_common(10))"
```
