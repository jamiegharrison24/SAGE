# Step 2 trial: GLiNER on terse signature titles

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

## Not done

- **NuNER Zero** (the plan's co-primary, MIT, token-classifier, expected
  better on multi-word spans) has not been run.
- **SecureBERT2.0-NER** has not been run — the plan's open question of whether
  its `System` type covers software products is still unanswered.
- **No integration.** `normalize.py` untouched; no pipeline measurement, and
  Step 0 still gates any accuracy claim.
- Threshold 0.85 is chosen from a 34-entity sample. Directional, not tight.
