"""Selects the alert-annotation taxonomy: SAGE's AIF, or MITRE ATT&CK.

SAGE annotates every alert with a stage code and renders attack graphs from
it. This module is the single place that decides *which* taxonomy those codes
come from, so the rest of the pipeline can stay unchanged.

    SAGE_TAXONOMY=aif                     (default -- unchanged behaviour)
    SAGE_TAXONOMY=mitre_hybrid_drop
    SAGE_TAXONOMY=mitre_hybrid_catchall
    SAGE_TAXONOMY=mitre_tactic_drop
    SAGE_TAXONOMY=mitre_tactic_catchall

The four MITRE arms vary on two axes, both of which are measurements rather
than settled choices (see `experiments/mitre_mapping/REPORT.md` 8a.5):

  * **hybrid vs tactic** -- how much detail survives. `tactic` collapses
    everything to ATT&CK's 14 tactics, leaving a single high-severity
    objective (`impact`) where AIF has 13, so a DoS graph and a ransomware
    graph merge. `hybrid` keeps technique identity at the medium and high
    tiers (4 objectives) and collapses only the low tier. Coarser graphs are
    worse for granularity but better for alert compression, which is one of
    the evaluation metrics -- hence both are built and measured.
  * **drop vs catchall** -- what happens to the ~25% of alert volume ATT&CK
    has no vocabulary for (Suricata protocol anomalies, policy traffic).
    `drop` discards them; `catchall` keeps them at low severity so the alert
    stream stays comparable to the AIF arm. The delta between the two
    measures how much of SAGE's graph structure rests on alerts ATT&CK
    cannot name.

**Severity is unchanged in every arm.** All codes keep AIF's convention that
the digit count encodes severity (1 low / 2 medium / 3 high), which is why no
pipeline stage needed editing: subsequence cutting, sink filtering and
objective selection all still read `len(str(mcat))`.
"""
import importlib
import os

from signatures import mitre_stages
from signatures.attack_stages import MicroAttackStage
from signatures.mappings import (
    macro_inv, micro, micro2macro, micro_inv, rev_smallmapping, small_mapping,
    verbose_micro,
)

TAXONOMY = os.environ.get("SAGE_TAXONOMY", "aif").strip().lower()
IS_MITRE = TAXONOMY.startswith("mitre_")

# Shape buckets in `ag_generation.shapes`: 0-2 oval (recon), 3-6 box
# (enabler), 7-11 hexagon (objective). AIF routes through micro2macro to pick
# one; for MITRE the severity tier *is* the bucket, which gives the same
# visual grammar without inventing a macro layer ATT&CK does not have.
_SHAPE_BY_SEVERITY = {1: 0, 2: 3, 3: 7}

if IS_MITRE:
    _mod = importlib.import_module(f"signatures.mitre_mapping_{TAXONOMY[len('mitre_'):]}")
    _sig_to_code = _mod.mitre_signature_to_code
    _code_to_name = _mod.mitre_code_to_name
    _small = _mod.mitre_small_mapping
    _rev_small = _mod.rev_mitre_small_mapping
    # Signatures with no ATT&CK vocabulary. Under `drop` they are absent from
    # the table and resolve here; the pipeline already discards NON_MALICIOUS
    # alerts, so reusing that code drops them through the existing path rather
    # than adding a second one.
    _UNMAPPED_FALLBACK = MicroAttackStage.NON_MALICIOUS.value
else:
    _sig_to_code = None
    _code_to_name = micro
    _small = small_mapping
    _rev_small = rev_smallmapping
    _UNMAPPED_FALLBACK = MicroAttackStage.NON_MALICIOUS.value


def active():
    """Name of the taxonomy in force, for run banners and report headers."""
    return TAXONOMY


def signature_to_code(signature, aif_resolver):
    """Stage code for a signature.

    `aif_resolver` is `alert_loading._get_attack_stage_mapping`'s original
    body, passed in so this module does not import the loader and create a
    cycle. It is called only in AIF mode.
    """
    if not IS_MITRE:
        return aif_resolver(signature)
    return _sig_to_code.get(signature.strip(), _UNMAPPED_FALLBACK)


def code_to_label(code):
    """Node label for a code -- `VULN_DISC` for AIF, `T1190` or
    `initial-access` for MITRE. The `Xxx.` prefix is stripped because
    `ag_generation` splits node names on `|` and the prefix carries no
    information for a reader."""
    name = _code_to_name.get(code, str(code))
    return name.split(".", 1)[1] if "." in name else name


def trace_symbol(code):
    """The `mcat` half of a FlexFringe `mcat|mserv` symbol."""
    return _small[code]


def code_for_symbol(symbol):
    return _rev_small[symbol]


def symbol_table():
    """The whole code -> symbol table, for callers that iterate it."""
    return _small


def severity(code):
    """Severity of a stage code: 1 low / 2 medium / 3 high.

    AIF and the tactic/hybrid levels encode this in the digit count; the
    technique level cannot (sequential codes are all two digits) and carries
    an explicit table instead. Both routes go through here so the pipeline
    never has to know which is in force.
    """
    return mitre_stages.severity_of_code(code)


def verbose_label(label):
    """Human-readable node text. AIF has a curated `verbose_micro` table;
    ATT&CK codes have no such table, so the label stands for itself
    (`T1190`, `discovery`)."""
    if not IS_MITRE:
        return verbose_micro[label]
    return label


def colour_index(code):
    """Index into `plotting.mcols` for a stage code.

    AIF routes micro -> macro -> colour. ATT&CK has no macro layer, so
    severity picks the colour band, matching how `shape_index` picks shapes.
    """
    if not IS_MITRE:
        return macro_inv[micro2macro[micro[code]]]
    return _SHAPE_BY_SEVERITY.get(len(str(code)), 0)


def shape_index(label):
    """Index into `ag_generation.shapes` for a node label.

    AIF keeps its existing micro -> macro route so shapes are unchanged. MITRE
    uses the severity tier, since ATT&CK has no macro layer and severity is
    exactly what the three shape buckets encode.
    """
    if not IS_MITRE:
        return macro_inv[micro2macro["MicroAttackStage." + label]]
    code = _rev_small.get(label)
    if code is None:
        for c, name in _code_to_name.items():
            if name.split(".", 1)[-1] == label:
                code = c
                break
    return _SHAPE_BY_SEVERITY.get(len(str(code)) if code is not None else 1, 0)


def label_to_code(label):
    """Inverse of `code_to_label`, used where the pipeline reconstructs a code
    from a rendered node name."""
    if not IS_MITRE:
        return micro_inv["MicroAttackStage." + label]
    for code, name in _code_to_name.items():
        if name.split(".", 1)[-1] == label:
            return code
    raise KeyError(label)
