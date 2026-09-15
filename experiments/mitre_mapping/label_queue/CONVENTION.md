# Labeling convention — signature → ATT&CK technique

> **The consolidated reference for this work is [`../REPORT.md`](../REPORT.md).**
> This file remains the detailed record for the labelling convention; read the report first.

Applies to every `queue_batch*.csv` → `labeled_batch*.csv` pass. Read this
before labeling, and keep it open while labeling; consistency across batches
matters more than any individual row being perfect.

## The blind rule (non-negotiable)

Label from **the signature text alone**. Do not look up the row's
`micro_attack_stage`, its `current_gt`/`gt_ids`, or what the pipeline
predicts for it.

Why this was written: the pipeline's dominant candidate source used to be
`bridge_table`, which mapped `micro_attack_stage` → technique. A labeler who
saw the stage largely re-derived that mapping, so the pipeline was scored
against a rewritten version of its own input — a set that reported a *higher*
number while carrying less information. `bridge_table` has since been removed
from the pipeline entirely (see `../STATUS.md` effort 9: 70% of scoreable rows
at only 34.8% accuracy — a structural ceiling from mapping ~12 broad stages
onto 52+ specific techniques, not a tunable weakness), so this specific
circularity can no longer occur.

**The rule stays in force anyway.** `micro_attack_stage` is still SAGE's own
coarse judgment about the alert, and a labeler anchoring on it will still tend
to reproduce that judgment rather than reasoning independently from the rule
text — which is exactly what makes the set worth having as an *independent*
check. The existing 100 rows earned their value by disagreeing with the old
bridge mapping — e.g. Shellshock `ARBITRARY_CODE_EXE` → T1203 rejected in
favour of T1190 (server-side, not client-side), and RDP admin login
`ROOT_PRIV_ESC` → T1068 rejected in favour of T1021.001 with the note "looks
like an upstream stage-classification error". Those disagreements are only
possible blind, and the same independence is valuable for whatever eventually
replaces `bridge_table`.

Consulting the ET rule body, its CVE, or its references is fine and
encouraged — that is rule-level evidence, not pipeline input.

**One exception inside the rule body: do not read its `mitre_technique_id` /
`mitre_tactic_id` metadata.** That field is exactly the pipeline's `declared`
source (Tier 0) — the highest-precision candidate it has. Labeling from it
scores the pipeline against a copy of its own answer, which is the same
circularity the blind rule exists to prevent, just entering through a
different door. Redact it before reading the body. Note that vendor tags are
not authoritative anyway: the original audit rejected 2 of 11 of them
(FortiOS SSL VPN tagged `T1082` when the exploit is `T1190`; Oracle JSF2 path
traversal tagged `T1083`, likewise `T1190`).

## Output columns

`signature, proposed_technique, rationale, label_source, reviewer_verdict, reviewer_notes`

- `proposed_technique` — see the value grammar below.
- `rationale` — one sentence, naming the observable behaviour that drove the
  choice. "web-server SQL injection attempt = exploitation of a public-facing
  app", not "looks like T1190".
- `label_source` — `model_proposed` for this pass. Becomes `human_confirmed`
  only when a person has actually checked the row.
- `reviewer_verdict` / `reviewer_notes` — left **empty** by the labelling
  pass. These are for the human review pass, and their emptiness is what marks
  a row as unconfirmed.

### `reviewer_verdict` values — ruled 2026-09-11

The column was in use before its values were ever defined here, which is how
`validate.py` came to treat *any* non-empty verdict as "confirmed" and score
43 rejected rows against the very labels a reviewer had rejected (2.2 points
of inflation; see `../STATUS.md`). Defined now:

| value | meaning | effect on scoring |
|---|---|---|
| `1` | reviewer checked `proposed_technique` against the source of truth and **agrees** | row is scored, and counts as a confirmed label |
| `0` | reviewer checked and the mapping is **false** | row is **excluded from evaluation entirely** — not scored, not counted as confirmed |
| *(empty)* | not yet reviewed | row is scored, and reported as unconfirmed |

A `0` is a statement that the *proposed label* is wrong, not that the
signature is unmappable. Excluding rather than re-scoring is deliberate: the
corrected label is not recorded in a machine-readable field, so there is
nothing to score against. Where a reviewer did write the correction into
`reviewer_notes` as free text ("t1021.004 is correct, t1110 is not"), that
signal is currently unused.

## Value grammar for `proposed_technique`

Matches the existing `hand_audit_sample*.csv` convention, which
`validate.py:parse_proposed` already parses:

| form | when | scored? |
|---|---|---|
| `T1190` | one clear technique | yes |
| `T1021.001` | a sub-technique is clearly warranted | yes |
| `ambiguous: T1059 / TA0011` | two defensible readings, no way to choose from the title | no (skipped) |
| `TA0011` | behaviour is real but only the tactic is determinable (e.g. reputation/blocklist hits with no protocol detail) | **no (skipped)** |
| `(none) - non-malicious` | policy/benign traffic detection, not an attack | no (skipped) |

Anything starting `ambiguous` or `(none)` is excluded from strict scoring.

**Tactic-only rows are also excluded**, and this is deliberate rather than an
oversight. `validate.py:parse_proposed` matches `T\d{4}`, which a `TA####`
tactic ID cannot satisfy, so those rows return `None` and are skipped. Scoring
them would be worse, not better: the pipeline emits *techniques*, so a
tactic-only target could never be hit, and including them would add guaranteed
misses that deflate the number without carrying information. Still label them
`TA0011` rather than forcing a technique — a recorded "only the tactic is
knowable" judgment is useful to a reviewer even when the harness skips it. The
run summary prints the tactic-only count so the exclusion stays visible.
Use them honestly — an inflated scoreable count with coin-flip labels is
worse than a smaller, trustworthy one.

## Granularity

Prefer the **top-level technique** unless the signature names the specific
mechanism. `T1021.001` for an explicit RDP login; plain `T1021` if the
signature only says "remote service access". Over-specifying invents
precision the signature text doesn't support.

## Recurring calls (decided once, apply everywhere)

- **Server-side exploitation of a listening service** → `T1190`, *not*
  `T1203`. T1203 is client-side (browser, document reader, mail client
  parsing attacker content). Shellshock over HTTP/SMTP/DNS to a server is
  T1190. This is the single most common miscall in the existing set.
- **Browser/document memory-corruption** → `T1203`.
- **Exploit-kit landing pages / drive-by** → `T1189`.
- **Reputation, blocklist, or "known hostile host" hits** with no protocol
  detail → `TA0011` (tactic only). Precedent: the existing
  "ET CNC Ransomware Tracker Reported CnC Server group 101" row.
- **Flood / amplification against a network or service** → `T1498`
  (add `.002` for reflection/amplification). **Resource exhaustion or crash
  of a single host/app** → `T1499`.
- **Malware or second-stage payload download** → `T1105`.
- **Chat/IM/VOIP protocol detection** (ET CHAT and similar) → generally
  `(none) - non-malicious`. Exception: IRC command signatures are
  `ambiguous: (none) / T1071.001`, since IRC is both ordinary traffic and a
  classic C2 channel and the title cannot separate them.
- **Scanning / enumeration**: network host sweep → `T1018`; port/service
  scan → `T1046`; targeted web-app scanning → `T1595.002`; generic active
  scanning → `T1595`.
- **Reading `/etc/passwd` or `/etc/shadow`** → `T1003.008`.

## Drift control

Label in batches of 50, not in one pass. After the run, ~20 rows get
re-labeled blind by the same process and compared to the first pass; that
agreement rate is reported alongside the set size as an honest ceiling on
what the set can tell you. A set of 500 model-proposed labels with a stated
consistency figure is defensible; 500 rows called "hand-audited" is not.
