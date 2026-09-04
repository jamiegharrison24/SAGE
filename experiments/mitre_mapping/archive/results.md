# MITRE ATT&CK signature-mapping: 7-method comparison

Branch `research/b2-mitre-eval`. Standalone research spike under
`experiments/mitre_mapping/` — does not touch the production pipeline.
Supersedes the earlier "just build the mapper" run (`report.md`); reuses its
`predictions.csv` as-is for method 1 (no regeneration).

**Missing prior artifacts note:** two inputs this task depends on
(`B4_mitre_replacement_design.md` and a "10-15 previously-flagged bad-call
signatures" list) were not present in the repo or in memory at the start of
this run. The design doc was supplied mid-session and used as specified. The
bad-call list was **reconstructed**, not recovered — see §5.

---

## 1. Ground truth

### 1a. Population and conflict checksum

Merged the four named containers in `signatures/alert_signatures.py`
(`ccdc_combined`, `usual_mapping`, `unknown_mapping`, `attack_stage_mapping` —
the last inverted from `{stage: [signatures]}` to `{signature: stage}`),
priority order `ccdc_combined > usual_mapping > unknown_mapping >
attack_stage_mapping` on conflicting labels. (`recent_suricata_alerts`, a
fifth container in the same file, is **not** one of the four named containers
and was excluded, per the task.)

| container | raw size |
|---|---:|
| ccdc_combined | 259 |
| usual_mapping | 394 |
| unknown_mapping | 47 |
| attack_stage_mapping (inverted) | 210 |
| **merged unique signatures** | **773** |
| **signatures with a conflicting label across containers** | **53** |

Both numbers match the task description exactly — the container set and
priority order reproduce the earlier (undocumented) analysis. Conflict detail
in `conflicts.csv`; full merged stage-level table in
`merged_ground_truth_stage.csv`.

(Earlier `report.md` reported 774 via a blanket `dir(sig_module)` sweep over
every dict/list in the file, which also picks up `recent_suricata_alerts` —
that's the source of the 773-vs-774 discrepancy between this run and the
original coverage-check spike.)

### 1b. Bridge table validation

The 34-row `MicroAttackStage -> MITRE` bridge table from
`B4_mitre_replacement_design.md` §2 was transcribed into `bridge_table.py`
and every technique/tactic ID validated against the live official ATT&CK
Enterprise STIX bundle (`enterprise-attack.json`, 697 non-deprecated/
non-revoked techniques, 15 tactics).

**Result: 0 validation problems.** Every ID the design doc drafted from
memory resolved cleanly against live data, including the one sub-technique
range (`SPEARPHISHING`: `T1566.001`–`T1566.003`, all three exist).

### 1c. Propagating to signature-level ground truth

Each of the 773 signatures inherits its `MicroAttackStage`'s bridge-table
entry, then partitions into three groups (this partition is the single
biggest methodological fix in this run — see §4):

| partition | count | meaning |
|---|---:|---|
| `technique_scoreable` | 562 | GT is one or more real technique IDs — the headline top-1/top-3 denominator |
| `tactic_only` | 122 | GT is a tactic ID (`DEFENSE_EVASION`→TA0005, `COMMAND_AND_CONTROL`→TA0011, `LATERAL_MOVEMENT`→TA0008, `PRIV_ESC`→TA0004) — scoreable only under "right tactic" |
| `unmappable` | 89 | `INIT` (sentinel), `NON_MALICIOUS` (reject class), `SERVICE_SPECIFIC` (no clean match) — excluded from every metric, counted explicitly |

**Confidence flags carried through from the bridge table** — 344 of 773 rows
(44.5%) inherit an `ambiguous` or `needs_review` confidence tag from the
design doc (`TARGET_IDEN`, `SURFING`, `INFO_DISC`, `USER_PRIV_ESC`,
`ROOT_PRIV_ESC`, `ARBITRARY_CODE_EXE`, `CONTENT_WIPE`, `DATA_EXFILTRATION`,
`DATA_DELIVERY`, plus the whole `SERVICE_SPECIFIC` bucket). **Scored results
below should be trusted less for these categories than for the `high`-
confidence ones** — this isn't a defect in the scoring, it's the bridge
table itself being honest about where SAGE's taxonomy and real ATT&CK don't
line up cleanly (see design doc §2's two flagged notes: the
phishing-3-ways collapse, and the tactic-vs-technique granularity mix).

Full table: `ground_truth_signatures.csv`.

---

## 2. Candidate technique list (Phase 2)

**Schema note:** `enterprise-attack.json` uses ATT&CK's current STIX shape
(the Oct-2025 data-source-v2 restructure). The old `x_mitre_data_sources`
field is gone from technique objects, and — checked directly against the
live bundle, not assumed — the replacement `x-mitre-data-component` objects
carry **no** back-reference to their parent `x-mitre-data-source` object
either (`x_mitre_data_source_ref` is null on all 109 components in this
bundle). The classic 38-category data-source vocabulary ("Network Traffic",
"DNS", etc.) exists as objects but is no longer joinable to techniques at
all in this schema version.

What **is** still joinable — because it's what actually gates each
technique's `detects` relationship — is the 109 `x-mitre-data-component`
names themselves, via:

```
attack-pattern <--detects-- detection-strategy --analytic_refs--> analytic
    --log_source_references[].data_component_ref--> data-component (.name)
```

So the Phase 2 filter classifies **data-component names** (still a small,
finite, STIX-sourced vocabulary — 109 fixed values, not free text) rather
than the now-orphaned data-source names. 98 of the 109 categories are
actually reachable from a technique via `detects` in this bundle; each was
classified category-by-category (not by keyword/substring match on
technique descriptions) as plausibly Suricata-observable or not, checking
description text for the non-obvious ones (`Response Content`/`Response
Metadata` turned out to be internet-scan network captures — included;
`Malware Content`/`Malware Metadata` are static payload/repository analysis
— excluded; `Social Media` is externally observed platform activity, not
Suricata-visible — excluded).

18 categories kept as network-plausible: `Active DNS`, `Passive DNS`,
`Domain Registration`, `Network Connection Creation`, `Network Share
Access`, `Network Traffic Content`, `Network Traffic Flow`, `Certificate
Registration`, `Firewall Disable/Enumeration/Metadata/Rule Modification`,
`Cloud Service Disable/Enumeration/Metadata/Modification`, `Response
Content`, `Response Metadata`.

| | count |
|---|---:|
| Full technique corpus (non-deprecated/revoked) | 697 |
| **Filtered candidate set** (>=1 network-plausible data component) | **286** |
| Techniques with zero detection-strategy-linked data component at all in this bundle | 45 |

**Diagnostic worth flagging:** of the 19 distinct technique IDs that appear
anywhere in the propagated ground truth, **5 are not in the filtered
candidate set** (`T1068`, `T1098`, `T1110`, `T1485`, `T1590`) — MITRE's own
`detects` graph doesn't document a network-observable detection strategy for
these, even though a Suricata alert can plausibly be evidence for some of
them (e.g. `T1590` Gather Victim Network Information from active-recon
traffic). This means **methods 2 and 4 (filtered-list methods) have a
structural top-1/top-3 ceiling below 100%** on any signature whose GT is one
of those 5 techniques — not a model failure, a candidate-list gap. Recorded
here rather than silently absorbed into the accuracy number.

Full detail: `candidate_techniques.json`.

---

## 3. Master comparison table (Phases 3+4)

All 6 embedding/k-NN methods run with fixed seeds (deterministic embedding
inference; k-NN tie-breaks resolved by vote count, then best neighbor
similarity, then lexicographic technique ID — no RNG anywhere in the
pipeline). Accuracy is reported both over the 562-signature
`technique_scoreable` subset (**headline**) and over all 773 (diluted, for
comparability) — **both are backed by solid ground truth** (the propagated
bridge-table labels, §1).

| method | top-1 (scoreable / all 773) | top-1 lenient-subtech (scoreable) | top-3 (scoreable / all 773) | right-tactic (scoreable / all 773) | median top-1 score |
|---|---:|---:|---:|---:|---:|
| 1. ATTACK-BERT, full list | 6.4% / 4.7% | 11.0% | 14.9% / 10.9% | 24.9% / 21.2% | 0.532 |
| 2. ATTACK-BERT, filtered list | 5.5% / 4.0% | 10.1% | 14.1% / 10.2% | 25.3% / 22.1% | 0.515 |
| 3. MiniLM, full list | 8.4% / 6.1% | 11.9% | 16.9% / 12.3% | 26.3% / 20.7% | 0.371 |
| 4. MiniLM, filtered list | 7.1% / 5.2% | 11.0% | 16.5% / 12.0% | 24.9% / 18.9% | 0.359 |
| 5. k-NN (k=5), ATTACK-BERT embeddings | **56.6%** / 51.0% | 56.6% | n/a (single answer) | 63.5% / 47.0% | n/a |
| 6. k-NN (k=5), MiniLM embeddings | **61.0%** / 54.9% | 61.0% | n/a (single answer) | 68.0% / 50.1% | n/a |
| 7. SMET pipeline | 13.2% / 9.6% | 15.1% | n/a (single answer) | 29.9% / 25.7% | n/a (softmax prob, not cosine — see §6) |

"lenient-subtech" credits a prediction that gets the *parent* technique right
even when the GT (or the prediction) is a sub-technique — see §6, this
matters most for method 7 since SMET's label space is parent-only.

**Read this table with the following caveat, not around it:** methods 5-6
are not measuring the same thing as methods 1-4 or 7. Because the ground
truth is *propagated from `MicroAttackStage`*, k-NN over the 773 labelled
signatures is really re-deriving the original 36-category clustering with a
technique-ID relabeling — it is the earlier `MicroAttackStage` classification
experiment wearing a technique-ID costume, scored on a much easier task
(nearest-neighbor among 773 hand-labelled peers) than methods 1-4/7 (picking
the right answer out of a large technique space with no access to the other
772 labelled examples at inference time). Their ~55-61% is not evidence that
technique-level classification from Suricata signatures is "mostly solved" —
it's evidence that signature text clusters cleanly by `MicroAttackStage`,
which was already known.

**Method 7 (SMET) beats methods 1-4 by a wide margin** (13.2% vs 5.5-8.4%
top-1 strict; 29.9% vs 24.9-26.3% right-tactic) while still solving the
harder, zero-labelled-neighbor problem that 1-4 solve — this is the most
interesting real result in this comparison. SMET's supervised
softmax-over-185-techniques classifier (trained on `CVE_annotated_dataset.xlsx`
+ an SRL-based sentence restructuring step, not raw nearest-neighbor lookup)
generalizes better than any zero-shot embedding-similarity approach tested
here. It's still far below the k-NN "cheat" methods (5-6) and nowhere near
production-usable in absolute terms, but it's the strongest genuinely
comparable result in the table.

Within methods 1-4 (the nearest-neighbor group): all four score in the same
low single-to-low-double-digit range, MiniLM slightly *outperforms*
ATTACK-BERT despite being a generic sentence model with no security-domain
pretraining, and filtering to the network-observable candidate list makes
things slightly *worse*, not better, for both models (partly explained by
the 5 missing GT techniques from §2). Right-tactic accuracy sits around
20-30% across the board (methods 1-4 and 7 alike) — the softer metric
roughly triples-to-quadruples top-1 but is still a minority of cases.

**Hub-collapse check** (most frequent top-1 predictions, `technique_scoreable`,
full detail in `scores.json`): ATTACK-BERT collapses hardest onto `T1505.004`
/ `T1505.003` (Server Software Component sub-techniques, 30-31 hits each out
of 562) regardless of candidate-list filtering; MiniLM collapses onto
`T1552.006` (Group Policy Preference credentials, 37-44 hits) and `T1498`
(Network DoS, 30-31 hits). SMET collapses onto `T1505` (Server Software
Component, 47 hits — same family ATTACK-BERT hub-collapses onto, interesting
convergence) and `T1046`/`T1105`/`T1499` (34-35 hits each). Every method
exhibits real hub collapse — a handful of techniques absorb a
disproportionate share of predictions regardless of the actual signature
content. The k-NN methods hub-collapse too (`T1203` 89-101 hits, ~16-18% of
all predictions) but onto plausible answers, consistent with them solving
an easier problem.

---

## 4. What the earlier design work got right — and the trap it flagged correctly

The design doc's own §3 flagged that severity (SAGE's digit-count encoding)
is out of scope here, and its §5 anticipated that technique-level accuracy
would be "a harder bar" than the 36-category test. Both held. The bigger
trap, not explicit in the design doc but implied by it, is the tactic/
technique granularity mix in the bridge table itself (§2's flagged rows):
`DEFENSE_EVASION`, `COMMAND_AND_CONTROL`, `LATERAL_MOVEMENT`, `PRIV_ESC` are
tactic IDs, and methods 1-4 only ever predict from the technique corpus — so
those 122 `tactic_only` signatures score a structural top-1/top-3 zero for
every nearest-neighbor method, always, regardless of model quality. Diluting
the headline number across all 773 (the "all_773" column above) silently
buries this; keeping the `technique_scoreable` partition as the headline
denominator is what stops it from being buried.

---

## 5. Reconstructed bad-call signatures

The task's "10-15 previously-flagged bad-call signatures" list was not found
in the repo, git history, or memory — only three names survived in the task
description itself (`/etc/shadow`, `Net User Command Response`, `Skype VOIP
version check`). **This table is reconstructed, not recovered**: those three
plus the 12 lowest-`score_1` rows from method 1's `predictions.csv`
(`bad_calls.py`, deterministic — no sampling).

| signature | GT (stage → ids) | 1: BERT full | 2: BERT filtered | 3: MiniLM full | 4: MiniLM filtered | 5: k-NN BERT | 6: k-NN MiniLM | 7: SMET |
|---|---|---|---|---|---|---|---|---|
| ET WEB_SERVER /etc/shadow Detected in URI | DATA_EXFILTRATION → T1041 | T1505.004 | T1036.012 | T1003.008 | T1056.003 | TA0011 | **T1041** | T1568 |
| ET ATTACK_RESPONSE Net User Command Response | COMMAND_AND_CONTROL → TA0011 | T1557.001 | T1557.001 | T1059.008 | T1059.008 | T1041 | T1041 | T1033 |
| ET CHAT Skype VOIP Checking Version (Startup) | NON_MALICIOUS → (none, unmappable) | T1123 | T1205.001 | T1552.008 | T1016.001 | T1046 | T1592 | T1082 |
| SERVER-MYSQL MySQL/MariaDB ... integer overflow attempt | END_POINT_DOS → T1499 | T1027.001 | T1030 | T1030 | T1030 | **T1499** | T1203 | T1030 |
| ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt | DATA_MANIPULATION → T1565 | T1505.003 | T1505.003 | T1213.006 | T1213.006 | **T1565** | **T1565** | T1190 |
| FILE-FLASH Adobe Flash Player use after free attempt | PRIV_ESC → TA0004 | T1027.006 | T1027.006 | T1204.002 | T1566.001 | **TA0004** | **TA0004** | T1036 |
| ET WEB_SPECIFIC_APPS ... Photo Galerie SQL Injection | ARBITRARY_CODE_EXE → T1203 | T1595.003 | T1595.003 | T1204.003 | T1204.003 | **T1203** | **T1203** | T1083 |
| ET CURRENT_EVENTS Malformed HeartBeat Response | VULN_DISC → T1595.002 | T1685.004 | T1205.002 | T1685.005 | T1546 | TA0004 | TA0004 | T1497 |
| ET CURRENT_EVENTS Malformed HeartBeat Request | VULN_DISC → T1595.002 | T1685.004 | T1205.002 | T1685.005 | T1546 | TA0004 | TA0004 | T1497 |
| ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT | DATA_MANIPULATION → T1565 | T1505.003 | T1505.003 | T1110.003 | T1056.003 | **T1565** | **T1565** | T1190 |
| ET CURRENT_EVENTS ... HeartBleed ... (Server Init Vuln Client) | PRIV_ESC → TA0004 | T1499.001 | T1499.001 | T1190 | T1190 | **TA0004** | **TA0004** | T1497 |
| ET CURRENT_EVENTS ... HeartBleed ... (Client Init Vuln Server) | PRIV_ESC → TA0004 | T1499.001 | T1499.001 | T1190 | T1190 | **TA0004** | **TA0004** | T1497 |
| ET WEB_SPECIFIC_APPS PHPOF ... Remote File Inclusion | DATA_DELIVERY → T1105 | T1218.001 | T1218.001 | T1218.008 | T1218.008 | **T1105** | **T1105** | T1505 |
| ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo) | INFO_DISC → T1592;T1590 | T1027.012 | T1027.012 | T1036.002 | T1027.003 | **T1592** | **T1592** | T1082 |
| GPL CHAT Google Talk Startup | NON_MALICIOUS → (none, unmappable) | T1213.005 | T1071.005 | T1213.005 | T1552.006 | T1592 | T1592 | T1102 |

Bold = exact match. Pattern holds throughout: methods 1-4 and 7 essentially
never land on the correct technique for these low-confidence cases (0/15
exact across all five — this subset was adversarially selected to be hard,
so this isn't representative of SMET's overall 13.2%), while the k-NN
methods land correctly on roughly half — consistent with the §3 caveat that
k-NN is solving an easier, different problem. SMET's misses here are at
least topically plausible rather than random (`T1190` Exploit Public-Facing
Application for both SQLi signatures — genuinely defensible; `T1497`
Virtualization/Sandbox Evasion for the malformed-HeartBeat pair — a
stretch but not nonsensical for "anomalous protocol behavior"). Note two of
the fifteen (`Skype VOIP`, `Google Talk Startup`) are `NON_MALICIOUS`/
`unmappable` in ground truth — every method's "prediction" for these is
unscoreable by construction, not a miss.

---

## 6. Method 7 (SMET) — unblocked; results above

The original blocker (`allennlp==2.10.1` requires `torch<1.13.0`, unavailable
for Python 3.12) was resolved by installing user-space Miniconda (no root
needed) and creating a Python 3.9 conda env — `torch==1.12.1` has wheels for
3.9, satisfying the pin. Full environment log in `smet_env_install3.log`.

Two further issues surfaced and were fixed once inside that env:

1. **`Pattern==3.6`** (the exact package SMET's `requirements.txt` pins) no
   longer exists on PyPI. Substituted the actively-installable community
   fork `Pattern3==3.0.0`, which installs under the top-level module name
   `pattern3` rather than `pattern` — added a 2-line shim package
   (`site-packages/pattern/en.py` re-exporting from `pattern3.text.en`) so
   `nlp_general.py`'s unmodified `from pattern.en import lexeme, pluralize`
   resolves.
2. **`Pattern3` itself has two real bugs** that are Python-3-incompatible
   (an empty `try:` block in `pattern3/text/tree.py`, and a
   `raise StopIteration` inside a generator in `pattern3/text/__init__.py`
   — both classic remnants of an abandoned 2to3 port, broken by PEP 479).
   Patched both **in the installed package, not in SMET's own source** —
   two trivial, behavior-preserving fixes (restore the intended
   `from itertools import izip` / fall through instead of
   `raise StopIteration`), not changes to SMET's modeling logic.

None of this touched `SMET.py`, `funs.py`, `parse_class.py`, or
`nlp_general.py` — the task's "call `map_attack_vector()` on raw signature
text, unmodified" requirement holds. Ran clean in 66.1s for all 773
signatures (`SMET/run_smet_batch.py`, `smet_batch.log`) — no crashes, no
`UNKNOWN` label lookups.

**Label-space check (as the task asked):** SMET's classifier outputs from a
fixed 185-label top-level-technique space (`id2ATT&CK_V2.json`), sourced
from an older ATT&CK snapshot (`id2mitre.json` has 594 entries vs our current
697-technique live corpus). Checked every one of the 125 distinct technique
IDs SMET actually predicted against the current live STIX bundle: **124
resolve cleanly; one does not** — `T1562` (Impair Defenses), which the live
bundle marks `revoked: true` with a `revoked-by` relationship pointing to
`T1685` (Disable or Modify Tools), evidently restructured after SMET was
trained. Flagged, not
silently coerced — `T1562` predictions score as a miss under strict and
lenient matching alike (`T1685` doesn't happen to be any signature's GT
here, so this doesn't move the reported numbers, but it would with a larger
GT set that included it). Separately: SMET's label space has **no
sub-techniques** at all — every prediction is a bare top-level ID — which is
why §3 reports a lenient-subtechnique variant specifically to give SMET a
fair comparison against methods that can predict `T1595.002`-style IDs
directly.

---

## Reproducing

```bash
# Phase 1: ground truth
python experiments/mitre_mapping/ground_truth.py         # merge + conflict checksum
python experiments/mitre_mapping/validate_bridge.py       # bridge table vs live STIX
python experiments/mitre_mapping/build_ground_truth.py    # propagate -> ground_truth_signatures.csv

# Phase 2: candidate technique list
python experiments/mitre_mapping/build_candidates.py      # -> candidate_techniques.json

# Phase 3: methods 2-6 (needs sentence-transformers/torch -- run under WSL/Linux)
python3 experiments/mitre_mapping/run_methods.py          # -> predictions_method{2..6}.csv
# method 1 reuses predictions.csv as-is (not regenerated)

# method 7 (SMET): needs its own Python 3.9 conda env, see SMET_STATUS.md +
# results.md section 6 for the exact setup (miniconda, Pattern3 substitution,
# two 1-line patches to the installed pattern3 package -- not to SMET itself)
~/miniconda3/envs/smet/bin/python experiments/mitre_mapping/SMET/run_smet_batch.py
                                                            # -> predictions_method7.csv

# Phase 4: score + report tables
python experiments/mitre_mapping/score.py                 # -> scores.json
python experiments/mitre_mapping/bad_calls.py              # -> bad_call_signatures.txt
python experiments/mitre_mapping/bad_call_table.py         # per-signature comparison table
```

All fixed-seed / deterministic (embedding inference has no sampling; k-NN
tie-breaks are rule-based). No production pipeline files touched.
