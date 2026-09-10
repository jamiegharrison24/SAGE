# Labeling convention — signature → ATT&CK technique

Applies to every `queue_batch*.csv` → `labeled_batch*.csv` pass. Read this
before labeling, and keep it open while labeling; consistency across batches
matters more than any individual row being perfect.

## The blind rule (non-negotiable)

Label from **the signature text alone**. Do not look up the row's
`micro_attack_stage`, its `current_gt`/`gt_ids`, or what the pipeline
predicts for it.

Why: the pipeline's dominant candidate source (`bridge_table`, ~60 of 80
scoreable rows) works by mapping `micro_attack_stage` → technique. A labeler
who sees the stage largely re-derives that mapping, so the pipeline gets
scored against a rewritten version of its own input. The result is a set that
reports a *higher* number while carrying less information.

The existing 100 rows earn their value precisely by disagreeing with the
bridge — e.g. Shellshock `ARBITRARY_CODE_EXE` → T1203 rejected in favour of
T1190 (server-side, not client-side), and RDP admin login `ROOT_PRIV_ESC` →
T1068 rejected in favour of T1021.001 with the note "looks like an upstream
stage-classification error". Those disagreements are only possible blind.

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
- `reviewer_verdict` / `reviewer_notes` — left **empty**. These are for the
  human review pass, and their emptiness is what marks the set as unconfirmed.

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
