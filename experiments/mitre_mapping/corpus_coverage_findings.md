# Why the number doesn't move: the corpus doesn't cover the eval distribution

Error analysis of the 229 misses in `validation_report.md` (36.6% / 22.2%
baseline, 2026-09-11). This supersedes "hub collapse" as the working diagnosis.

## 1. Hub collapse is already solved — and I kept citing a stale number

The pipeline predicts `T1190` on **113/361** rows. The true `T1190` count is
also **113/361**. It is calibrated on the hub *exactly*.

The "28.5% true base rate" quoted throughout `entity_normalisation_plan.md`
was measured on the **pre-Step-0** set. The `reviewer_verdict` scoring fix
changed the base rate to 31.3%, which is where the pipeline already sits. So
§6's prediction ("T1190 share stable or slightly down") was aimed at a problem
that the scoring fix had already dissolved. That is a better explanation for
Step 2's null than the one recorded in `entity_ner/findings.md`, and it should
be read alongside it.

## 2. Accuracy tracks how many training examples a technique has

| bucket | rows | accuracy | classes |
|---|---|---|---|
| head (>=20 eval examples) | 189 | **43.9%** | 3 |
| mid (3-19) | 137 | **31.4%** | 21 |
| tail (<=2) | 35 | **17.1%** | 27 |

(83 + 43 + 6 = 132 = the micro numerator, so this reconciles exactly.)

## 3. The smoking gun: 21 `ET DOS` rows, one mislabeled neighbour

Every `ET DOS` signature in the eval set — 21 of them — is predicted
**`T1495` Firmware Corruption**, which is unrelated to denial of service.

Cause: the three corpora contain **exactly one** row labeled `T1495`, and its
text is `"Cisco Denial of Service"` (Sigma). Every `ET DOS` title normalises to
something containing "denial of service", so that single mislabeled row is the
nearest neighbour for the entire category.

It wins because there is almost nothing else to retrieve.

## 4. The real problem: supply vs demand

| technique | eval rows (demand) | corpus rows (supply) | supply source |
|---|---:|---:|---|
| `T1595.002` vuln scanning | 44 (12.2%) | **8** | sigma 1, elastic 7 |
| `T1499` endpoint DoS | 32 (8.9%) | **9** | sigma 3, elastic 6 |
| `T1498` network DoS | 12 (3.3%) | **10** | et 1, sigma 3, elastic 6 |

**Three techniques are 24.4% of the eval set and have 27 training examples
between them — 0.08% of a 31,825-row corpus.**

Why, from each corpus's label distribution:

```
et       26,644 rows but only  45 techniques -- 68% is just three:
         T1190 23.2%, T1071 22.9%, T1568 22.2%
sigma     3,289 rows, 398 techniques -- Windows/host: T1059.001 PowerShell,
         T1218 signed-binary proxy, T1112 registry
elastic   1,892 rows, 444 techniques -- cloud/endpoint: T1078 valid accounts,
         T1098 account manipulation, T1562 impair defenses
```

The eval set is **network IDS signatures**. ET is 83% of the corpus but
teaches only 45 techniques, concentrated in three. Sigma and Elastic carry the
technique diversity but in the wrong register — host, endpoint and cloud
detections, not network traffic.

So the corpus is large and almost orthogonal to the test distribution.

## 5. This re-reads every previous negative result

One cause explains all of them:

- **Splunk rejected** (effort 12, 0/20 retrieval) — host-based register.
- **Elastic marginal** (+1.3 macro via IDF dilution, 6.7% own-retrieval
  accuracy) — endpoint register.
- **MISP galaxy 1.0% hit rate** — host-side malware names.
- **Entity normalisation null** (Steps 1-3) — normalising text cannot create
  training examples for a class that has eight.
- **Layer D's three failures** — an LLM cannot retrieve what is not there.

Every lever pulled so far has been a *representation* lever. The binding
constraint is *coverage*.

## 6. What to do — and the trap in the obvious version

The obvious fix is to label ET's own `ET DOS` category (hundreds of rules) as
`T1498`/`T1499` by rule, giving the missing examples immediately.

**Do not do this without care.** `CONVENTION.md` instructs human labellers to
map "flood/amplification → T1498, resource exhaustion of a single host →
T1499". A category-to-technique rule in the *training* corpus, scored against
labels a human produced with the same rule, is scoring the pipeline against a
copy of its own input. That is exactly the `bridge_table` circularity that
effort 9/10 removed for capping at 34.8%.

Defensible options, in order of preference:

1. **Find a labeled corpus in the right register.** Network-IDS rules with
   genuine ATT&CK metadata. The register-match criterion from effort 12
   applies, and the two corpora that failed it should have predicted this.
2. **Harvest ET's own declared tags more aggressively.** Real metadata is not
   circular. Tier 0 currently recovers 39 rows; only 11 of 62 matched bodies
   carry a tag, but ETPRO/Snort sources were never exhausted.
3. **Hold out honestly.** If a category rule is used to build training data,
   the eval rows in that category must be excluded from scoring, or the number
   is meaningless.

## 7. The number to watch

Not micro. **Accuracy on the mid/tail buckets (31.4% / 17.1%)**, and the
supply column in §4. Micro is dominated by three head classes and will move
for reasons that have nothing to do with whether the pipeline got better.
