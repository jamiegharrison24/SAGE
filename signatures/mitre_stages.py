"""MITRE ATT&CK tactics as a drop-in replacement for the Action-Intent Framework.

SAGE annotates every alert with a `MicroAttackStage` integer whose **digit
count encodes severity** -- 1 digit = low (scanning), 2 = medium (enabler),
3 = high (exploitation/objective). That convention is load-bearing in three
places:

  * `episode_sequence_generation.py` cuts subsequences where severity DROPS
    (`len(str(mcats[i])) > len(str(mcats[i + 1]))`), which is what defines a
    distinct attack attempt;
  * `model_learning.py` discards state IDs from low-severity sinks and keeps
    medium/high ones;
  * `ag_generation.py` builds one graph per victim per *high-severity*
    objective.

**This module changes none of it.** ATT&CK's 14 enterprise tactics fit the
digit-count encoding exactly -- 3 low, 9 medium, 2 high -- so the substitution
is a swap of the lookup table and the trace symbols, with no edit to any
pipeline stage.

Why tactics rather than techniques. Techniques do not fit: the observed
signatures alone use **18** low-tier techniques (discovery and
reconnaissance), where the encoding allows 9, so a technique-level
substitution would force either an architectural change to how severity is
derived or a lossy renumbering. Tactics also keep the alphabet close to AIF's
own size, which matters because FlexFringe symbols are `mcat|mserv` pairs and
a much larger alphabet means sparser transitions and more sink states.
Signatures still carry their technique label (see
`experiments/mitre_mapping/label_queue/`); it is available for node
annotation, it just does not drive graph structure.

Tier boundaries mirror AIF's own logic rather than inventing one. Note that
*exploitation* is MEDIUM in AIF (`PUBLIC_APP_EXP` = 16, `REMOTE_SERVICE_EXP`
= 17) and only impact/exfiltration is HIGH -- so `initial-access` sits in the
medium tier here, alongside the AIF stage it replaces.
"""

# Tactic shortname -> (code, trace symbol). Codes follow AIF's convention:
# the DIGIT COUNT is the severity, so 1-9 is low, 10-99 medium, 100+ high.
# Assigned by hand rather than generated, because there are fourteen of them
# and they do not change -- the same reason `small_mapping` is hand-written.
TACTIC_CODES = {
    # LOW -- reconnaissance and enumeration, before the attacker acts
    "reconnaissance":       (1, "recon"),
    "resource-development": (2, "resDev"),
    "discovery":            (3, "discov"),

    # MEDIUM -- enablers: getting in, staying in, moving, preparing
    "initial-access":       (10, "initAcc"),
    "execution":            (11, "exec"),
    "persistence":          (12, "persist"),
    "privilege-escalation": (13, "privEsc"),
    "defense-evasion":      (14, "evasion"),
    "credential-access":    (15, "credAcc"),
    "lateral-movement":     (16, "lateral"),
    "collection":           (17, "collect"),

    # HIGH -- the attacker's objective is realised
    "command-and-control":  (100, "CnC"),
    "exfiltration":         (101, "exfil"),
    "impact":               (102, "impact"),
}

# ---------------------------------------------------------------------------
# Why `command-and-control` is HIGH, against ATT&CK's own kill-chain logic.
#
# ATT&CK treats C2 as an *enabler*: the attacker is maintaining access, not
# realising a goal. Tiering it MEDIUM on that reasoning was the first build,
# and it cost **29 of 36 victims** their attack graphs on cptc-2017 (104 AGs
# -> 9). Attack graphs are generated per high-severity objective, and AIF
# treats `DATA_DELIVERY` and `DATA_EXFILTRATION` as terminal objectives while
# the signatures behind them label as C2 techniques (T1071, T1105) under
# ATT&CK. Demote C2 and those objectives simply cease to exist.
#
# The project proposal settles this explicitly -- its Severity Configuration
# section asks for "a configurable mapping from MITRE ATT&CK tactics to
# severity tiers, which will **preserve the original implementation's
# behaviour**". Preserving behaviour means AIF's objectives stay objectives,
# so C2 is HIGH here. This is implementing the spec, not tuning for a result.
#
# `initial-access` deliberately stays MEDIUM even though AIF's `PHISHING` is
# high: that tactic also carries `T1190`, and AIF puts exploitation at medium
# (`PUBLIC_APP_EXP` = 16). Promoting it would move far more than it fixed.
#
# The ATT&CK-faithful tiering is a recorded finding rather than a live arm --
# see REPORT.md 8a.7. Flip C2 back to (18, "CnC") and rebuild to reproduce it.
# ---------------------------------------------------------------------------

# Kill-chain order, for reporting and for resolving multi-tactic techniques.
TACTIC_ORDER = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
)

# Signatures whose label carries no ATT&CK technique -- Suricata protocol
# anomalies, policy traffic, benign chat. ATT&CK has no vocabulary for them;
# AIF gives them a low-severity stage. Used only by the "catchall" arm, which
# exists so the delta against the "drop" arm measures how much of SAGE's graph
# structure rests on alerts ATT&CK cannot name.
UNMAPPED_CODE = 9
UNMAPPED_NAME = "MitreTactic.UNMAPPED"
UNMAPPED_SYMBOL = "unmapped"


def severity_of(code):
    """1 low / 2 medium / 3 high -- identical to what the pipeline already
    computes as `len(str(code))`. Provided for readability in new code; the
    existing pipeline sites are left untouched."""
    return len(str(code))


def short_symbol(technique_id):
    """Trace symbol for a technique -- `T1190` -> `t1190`, `T1021.002` ->
    `t1021_002`. Used only by the hybrid level, where medium and high codes
    keep technique identity.

    FlexFringe symbols are `mcat|mserv` pairs, so this half must contain no
    `|` or whitespace. Mechanical rather than mnemonic, unlike the hand-written
    tactic symbols above: the technique set is open-ended and a hand-written
    table would rot.
    """
    return technique_id.lower().replace(".", "_")


def tactic_for(tactic_shortnames):
    """The tactic a technique is recorded under, for severity purposes.

    A technique with several tactics takes the **highest-severity** one:
    `T1190` is initial-access (medium), `T1486` is impact (high), and a
    technique spanning discovery and collection resolves to collection
    (medium). Taking the max rather than the kill-chain-first entry is
    deliberate -- the tier decides whether a state can terminate an attack
    graph, and under-calling that hides objectives, the more damaging of the
    two errors.
    """
    known = [t for t in tactic_shortnames if t in TACTIC_CODES]
    if not known:
        return None
    return max(known, key=lambda t: TACTIC_CODES[t][0])
