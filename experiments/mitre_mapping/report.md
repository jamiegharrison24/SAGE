# MITRE ATT&CK signature-mapping experiment

Standalone research spike (branch `research/b2-mitre-eval`, does not touch the
production pipeline). Maps Suricata signature strings to MITRE ATT&CK
Enterprise techniques by semantic similarity, using `basel/ATTACK-BERT`
sentence embeddings over the live STIX technique corpus (no hardcoded
technique list).

## Coverage: raw alert signatures vs. the hardcoded dicts

`signatures/alert_signatures.py` maps signature strings to `MicroAttackStage`
values across several containers (`usual_mapping`, `unknown_mapping`,
`ccdc_combined`, and a handful of per-category lists referenced by
`attack_stage_mapping`). The union of every string in those containers is
**774** unique signatures. Any signature *not* in that union silently
defaults to `NON_MALICIOUS` at runtime (`alert_loading._get_attack_stage_mapping`).

Computed by `coverage_check.py` against the raw alert JSON (decompressed
`.gz` files) in `alerts/cptc-2017/`, `alerts/cptc-2018/`, `alerts/ccdc/`:

| dataset     | distinct signatures | covered | uncovered |
|-------------|---------------------:|--------:|----------:|
| cptc-2017   | 168                  | 168     | 0         |
| cptc-2018   | 225                  | 225     | 0         |
| ccdc        | 206                  | 102     | 104       |
| **combined**| **530**              | **426** | **104**   |

Notes:
- cptc-2017's 168 matches the count already confirmed independently.
- cptc-2018's 225 is the previously-open number — cptc-2018 also has full
  (100%) coverage, same as cptc-2017.
- ccdc's 206 distinct signatures matches the number attributed to
  `FINDINGS.md`. However, I could not find "only 20 explicitly mapped"
  anywhere in `docs/FINDINGS.md` or in git history (`git log --all -S`) — the
  actual measured coverage is 102/206 covered, 104/206 uncovered. Flagging
  this discrepancy rather than assuming the "20" figure; worth double-checking
  where that number originated.
- All 104 uncovered signatures come from ccdc (cptc-2017/2018 are fully
  covered). These are exactly the ones a hardcoded dict can't classify but a
  semantic-similarity model might — see `uncovered_signatures.txt`.

## Method

1. `fetch_techniques.py` downloads the live MITRE ATT&CK Enterprise STIX
   bundle (`mitre-attack/attack-stix-data`) via `mitreattack-python`, extracts
   name + description for every non-revoked/non-deprecated technique
   including sub-techniques (697 techniques as of this run), and caches them
   to `techniques.json`.
2. `build_predictions.py` embeds every technique's `"{name}: {description}"`
   text with `basel/ATTACK-BERT` (sentence-transformers) — this is the fixed
   reference set.
3. It then takes the union of all 774 unique signature strings across every
   container in `signatures/alert_signatures.py`, embeds each the same way,
   and computes cosine similarity (dot product over L2-normalized embeddings)
   against every technique.
4. For each signature, the top-3 closest techniques and their similarity
   scores are written to `predictions.csv`:
   `signature, predicted_technique_1, score_1, predicted_technique_2, score_2,
   predicted_technique_3, score_3`.
5. The same top-3 lookup is also run over the 104 uncovered signatures (the
   ones from `uncovered_signatures.txt` that appear in the raw datasets but
   aren't in the hardcoded dicts) and appended to the same `predictions.csv`
   as a second section, after a blank line and a `# uncovered` marker row,
   with the header repeated.

No accuracy scoring or ground-truth comparison is performed here — this is
purely running the model and saving its output for later evaluation.

## Reproducing

```bash
pip install --user --break-system-packages sentence-transformers mitreattack-python stix2
python3 experiments/mitre_mapping/coverage_check.py     # coverage table + uncovered_signatures.txt
python3 experiments/mitre_mapping/fetch_techniques.py   # techniques.json (cached STIX pull)
python3 experiments/mitre_mapping/build_predictions.py  # predictions.csv
```
