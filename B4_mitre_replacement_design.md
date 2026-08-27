# B4 (Option 2): replacing MicroAttackStage with real MITRE ATT&CK — design note

*Follow-on to `B4_mapping_method_research.md`. Decision made 2026-08-26: the target output of the mapping layer should be real MITRE ATT&CK technique/tactic IDs, not SAGE's own 36-category `MicroAttackStage` taxonomy. This note works out what that actually requires before an ATTACK-BERT test can be built.*

## 1. Why the earlier test plan doesn't directly work here

The 773 hand-labelled `(signature → MicroAttackStage)` pairs are ground truth for *SAGE's* categories. They are not ground truth for real ATT&CK technique IDs — nobody has labelled which technique each Suricata signature corresponds to. So "run ATTACK-BERT and see which MITRE thing it maps to" needs an answer key to check it against, and building that answer key is the actual first problem.

## 2. The fix: a 36-row bridge table, not 773 individual judgements

Rather than hand-labelling all 773 signatures against the full ATT&CK technique list (slow, and duplicates work the original `MicroAttackStage` labelling already did), map each of the 36 `MicroAttackStage` categories to its best-fit MITRE ATT&CK technique or tactic **once**, then propagate: every signature already labelled `SERVICE_DISC` inherits whatever `SERVICE_DISC` maps to.

**This table must be authored independently of ATTACK-BERT** (by hand / domain knowledge / MITRE's own documentation), not by asking ATTACK-BERT to do the matching. If ATTACK-BERT is used to build the ground truth it will then be evaluated against, the accuracy number is circular and not defensible.

Draft below — confidence-flagged, not final. Several are genuine technique matches (marked ✅), a few are ambiguous or context-dependent (⚠️), and a handful are actually MITRE **tactic** names, not techniques (🔷) — SAGE's own taxonomy mixes granularities here, which is itself worth a sentence in the paper.

| MicroAttackStage | Best MITRE match (draft) | Confidence |
|---|---|---|
| `INIT` | *(sentinel value, not a real attack stage — no mapping)* | — |
| `TARGET_IDEN` | T1590 Gather Victim Network Information | ⚠️ |
| `SURFING` | T1595 Active Scanning | ⚠️ |
| `SOCIAL_ENGINEERING` | T1566 Phishing | ✅ |
| `HOST_DISC` | T1018 Remote System Discovery | ✅ |
| `SERVICE_DISC` | T1046 Network Service Discovery | ✅ |
| `VULN_DISC` | T1595.002 Active Scanning: Vulnerability Scanning | ✅ |
| `INFO_DISC` | T1592 / T1590 Gather Victim Host/Network Information | ⚠️ context-dependent |
| `USER_PRIV_ESC` | T1068 Exploitation for Privilege Escalation | ⚠️ |
| `ROOT_PRIV_ESC` | T1068 Exploitation for Privilege Escalation | ⚠️ (same as above — SAGE splits user/root, ATT&CK doesn't) |
| `NETWORK_SNIFFING` | T1040 Network Sniffing | ✅ |
| `BRUTE_FORCE_CREDS` | T1110 Brute Force | ✅ |
| `ACCT_MANIP` | T1098 Account Manipulation | ✅ |
| `TRUSTED_ORG_EXP` | T1199 Trusted Relationship | ✅ |
| `PUBLIC_APP_EXP` | T1190 Exploit Public-Facing Application | ✅ |
| `REMOTE_SERVICE_EXP` | T1210 Exploitation of Remote Services | ✅ |
| `SPEARPHISHING` | T1566.001–.003 Spearphishing (sub-techniques) | ✅ |
| `SERVICE_SPECIFIC` | *(no clean match — catch-all)* | ❌ needs manual review |
| `DEFENSE_EVASION` | 🔷 TA0005 Defense Evasion (tactic, not a technique) | 🔷 |
| `COMMAND_AND_CONTROL` | 🔷 TA0011 Command and Control (tactic) | 🔷 |
| `LATERAL_MOVEMENT` | 🔷 TA0008 Lateral Movement (tactic) | 🔷 |
| `ARBITRARY_CODE_EXE` | T1203 Exploitation for Client Execution (alt: T1059) | ⚠️ |
| `PRIV_ESC` (generic) | 🔷 TA0004 Privilege Escalation (tactic — this is a fallback bucket) | 🔷 |
| `END_POINT_DOS` | T1499 Endpoint Denial of Service | ✅ |
| `NETWORK_DOS` | T1498 Network Denial of Service | ✅ |
| `SERVICE_STOP` | T1489 Service Stop | ✅ |
| `RESOURCE_HIJACKING` | T1496 Resource Hijacking | ✅ |
| `DATA_DESTRUCTION` | T1485 Data Destruction | ✅ |
| `CONTENT_WIPE` | T1561 Disk Wipe | ⚠️ overlaps with Data Destruction |
| `DATA_ENCRYPTION` | T1486 Data Encrypted for Impact | ✅ |
| `DEFACEMENT` | T1491 Defacement | ✅ |
| `DATA_MANIPULATION` | T1565 Data Manipulation | ✅ |
| `DATA_EXFILTRATION` | T1041 Exfiltration Over C2 Channel (alt: tactic-level TA0010) | ⚠️ |
| `DATA_DELIVERY` | T1105 Ingress Tool Transfer | ⚠️ ambiguous — could also be Initial Access delivery |
| `PHISHING` | T1566 Phishing | ✅ (redundant with `SOCIAL_ENGINEERING`/`SPEARPHISHING` — see below) |
| `NON_MALICIOUS` | *(no MITRE equivalent — not an attack; must stay a reject class)* | — |

**Two things worth flagging to your supervisor, separate from the accuracy test:**

1. `SOCIAL_ENGINEERING`, `SPEARPHISHING`, and `PHISHING` all collapse to variants of T1566 — SAGE's taxonomy distinguishes them, real ATT&CK mostly doesn't at this level. Worth a sentence on where SAGE's categories are finer-grained than ATT&CK and where they're coarser.
2. `DEFENSE_EVASION`, `COMMAND_AND_CONTROL`, `LATERAL_MOVEMENT`, and the `PRIV_ESC` fallback are tactic-level, not technique-level. If Option 2's output space mixes tactics and techniques, decide (and state explicitly) whether that's intentional — it probably should be, since forcing a single technique onto a genuinely tactic-level signature would be less accurate, not more.

## 3. What this table is *not* solving: severity

`MicroAttackStage`'s integer values aren't arbitrary — 1-digit/2-digit/3-digit encodes low/medium/high severity, and episode cutting, sink detection, and trace generation all read that encoding directly (`attack_stages.py`, `episode_sequence_generation.py`, `model_learning.py`). Real MITRE technique/tactic IDs carry no such severity signal.

This is a separate design problem from "does ATTACK-BERT map signatures correctly" and shouldn't be solved inside the accuracy test. Two directions, for a later task:
- Define a tactic → severity tier mapping of your own (recon/discovery tactics = low, credential-access/lateral-movement = medium, impact/exfiltration = high — same spirit as the current scheme, just keyed on real ATT&CK tactics instead of SAGE's categories), and encode it the same digit-count way so the rest of the pipeline needs zero changes.
- Or refactor the pipeline to take severity as an explicit field instead of inferring it from the label's numeric value — bigger change, cleaner long-term.

Flag this as its own B-task rather than folding it into B4/the ATTACK-BERT test.

## 4. Scoping the technique candidate set

Enterprise ATT&CK has on the order of 200 techniques (600+ counting sub-techniques). Not all of them are observable from network IDS alerts at all (MITRE's own data-source metadata tags roughly 4 techniques as having no network-traffic detection source, and plenty more are host-only). Restricting the candidate set ATTACK-BERT compares against to techniques whose `x_mitre_data_sources` includes Network Traffic will cut noise and avoid nonsensical matches — pull this filter from MITRE's own machine-readable data (the `attack-stix-data` repo or the `mitreattack-python` library), don't hand-curate it.

## 5. Revised test plan for Claude Code

1. Pull the live official ATT&CK Enterprise technique list (STIX data), not a hardcoded list — versions drift.
2. Validate every ID in the §2 draft table against that live data; flag and fix any that don't resolve (I drafted these from memory, not a live lookup — don't trust the exact T-numbers without this check).
3. Filter the candidate technique set to those with Network Traffic as a listed detection data source.
4. Propagate the validated bridge table across the 773 signatures to build the real ground truth.
5. Run the same three-method comparison as before (ATTACK-BERT zero-shot, generic-model baseline, k-NN against labelled examples) — but against technique/tactic embeddings and the propagated labels, not `MicroAttackStage` descriptions.
6. Report accuracy same as before, plus: how often the top prediction is right *tactic*, wrong *technique* (a softer, still-useful correctness measure) — since technique-level accuracy will be a harder bar than the earlier 36-category test.
