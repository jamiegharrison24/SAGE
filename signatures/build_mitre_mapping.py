"""Generate the ATT&CK-tactic equivalents of `alert_signatures.py` / `mappings.py`.

Produces `signatures/mitre_mapping_generated.py`, the ATT&CK counterpart of
SAGE's hand-built AIF lookup:

    signature -> tactic code    (digit count = severity, as AIF; see mitre_stages.py)
    code      -> "MitreTactic.initial-access"
    code      -> "initAcc"      (trace symbol)

plus `mitre_signature_to_technique`, which carries the technique label for
node annotation. Techniques do not drive graph structure -- see
`mitre_stages.py` for why tactics are the level that fits SAGE's severity
encoding.

**Why a lookup table and not the classifier.** SAGE's AIF side
(`alert_signatures.py`) is a hand-built dictionary with no model in it. If the
ATT&CK side ran through a classifier scoring ~70%, the attack-graph comparison
would be *perfect AIF against 70% ATT&CK*, and every structural difference
would be confounded -- unattributable to the taxonomy rather than to mapping
error. The hand-labelled signatures are the same kind of object as
`alert_signatures.py`, which is what holds mapping quality constant across the
two arms. See `experiments/mitre_mapping/REPORT.md` §8a.1.

**The unmapped arm.** ~25% of alert volume carries a `(none)`/`ambiguous`/
tactic-only label -- mostly Suricata protocol-parser anomalies and policy
traffic. ATT&CK has no vocabulary for them; AIF gives them a low-severity
stage. Both readings are defensible and the difference is itself a
measurement, so both are built:

    --unmapped drop      omit them; the ATT&CK arm simply sees fewer alerts
    --unmapped catchall  assign UNMAPPED_CODE (low severity), keeping the
                         alert stream comparable to the AIF arm

Usage:
    python -m signatures.build_mitre_mapping --unmapped drop
    python -m signatures.build_mitre_mapping --unmapped catchall
"""
import argparse
import csv
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
EXP = os.path.join(ROOT, "experiments", "mitre_mapping")
STIX = os.path.join(EXP, "attack_mapper", "data", "enterprise-attack.json")

sys.path.insert(0, HERE)
from mitre_stages import (  # noqa: E402
    TACTIC_CODES, TACTIC_ORDER, UNMAPPED_CODE, UNMAPPED_NAME,
    UNMAPPED_SYMBOL, severity_of, short_symbol, tactic_for,
)
TIER_SEVERITY = {"low": 1, "medium": 2, "high": 3}

TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

LABEL_SOURCES = (
    os.path.join(EXP, "label_queue", "labeled_batch*.csv"),
    os.path.join(EXP, "attack_mapper", "data", "hand_audit_sample*.csv"),
    os.path.join(EXP, "attack_mapper", "data", "labeled_set_v2.csv"),
)


def load_labels():
    """signature -> raw label string, first writer wins (batches are ordered)."""
    out = {}
    for pattern in LABEL_SOURCES:
        for path in sorted(glob.glob(pattern)):
            with open(path, encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    sig = (row.get("signature") or "").strip()
                    lab = (row.get("proposed_technique") or "").strip()
                    if sig and lab and sig not in out:
                        out[sig] = lab
    return out


def technique_tactics_index():
    """technique_id -> [tactic shortname, ...] from the STIX bundle."""
    with open(STIX, encoding="utf-8") as fh:
        bundle = json.load(fh)
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if tid:
            index[tid] = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                          if p.get("kill_chain_name") == "mitre-attack"]
    return index


def assign_hybrid_codes(tech_tier):
    """technique -> code, keeping technique identity where it matters.

    `tech_tier` is {technique_id: severity}. The rule:

      * **low tier collapses to its tactic** (codes 1-3). 18 low-tier
        techniques do not fit the nine single-digit codes the encoding
        allows, and scanning/discovery is where granularity matters least --
        AIF itself carries only 7 low stages.
      * **medium and high stay technique-level** (10-99 and 100+, 30 and 4
        techniques against 90 and 900 slots). This is where graph meaning
        lives: high-tier codes become attack-graph *objectives*, so
        collapsing them to `impact` would merge a denial-of-service graph
        with a ransomware one.

    Digit count still encodes severity, so no pipeline stage changes.
    Allocation is sorted for determinism -- codes end up inside FlexFringe
    trace symbols, and a reshuffle would make two runs incomparable.
    """
    codes = {}
    next_code = {2: 10, 3: 100}
    for tid in sorted(tech_tier):
        tier = tech_tier[tid]
        if tier == 1:
            continue  # handled by the caller, which knows the tactic
        codes[tid] = next_code[tier]
        next_code[tier] += 1
        if tier == 2 and next_code[2] > 99:
            raise SystemExit("medium tier overflow: more than 90 techniques")
    return codes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unmapped", choices=["drop", "catchall"], required=True)
    ap.add_argument("--level", choices=["tactic", "hybrid", "technique"], default="hybrid",
                    help="'tactic' annotates every alert with its ATT&CK "
                         "tactic (14 codes, 1 objective type). 'hybrid' keeps "
                         "technique identity at the medium and high tiers and "
                         "collapses only the low tier to tactics -- see "
                         "REPORT.md 8a.5 for why this is a measured "
                         "trade-off rather than a settled choice.")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    labels = load_labels()
    tactics_index = technique_tactics_index()

    # Pass 1: resolve every signature to (tactic, technique), or a decline.
    resolved, declines, no_tactic = {}, [], []
    for sig, lab in labels.items():
        if not TECH_RE.match(lab):
            declines.append(sig)
            continue
        tactic = tactic_for(tactics_index.get(lab, []))
        if tactic is None:
            # A technique the STIX bundle records no kill-chain phase for
            # cannot be placed in a severity tier. Treated as a decline rather
            # than guessed: a wrong tier silently changes subsequence cutting.
            no_tactic.append((sig, lab))
            continue
        resolved[sig] = (tactic, lab)

    # Pass 2: allocate codes at the requested level.
    # Seed with the tactic tables only where tactic codes are actually used.
    # At the `technique` level they are not, and seeding would collide: the
    # technique codes start at UNMAPPED_CODE+1 = 10, which is exactly where
    # the medium tactic codes live (10-18), so entries would overwrite each
    # other and a code would resolve to whichever wrote last.
    if args.level == "technique":
        code_to_name, code_to_symbol = {}, {}
    else:
        code_to_name = {c: f"MitreTactic.{t}" for t, (c, _) in TACTIC_CODES.items()}
        code_to_symbol = {c: s for _, (c, s) in TACTIC_CODES.items()}
    sig_to_code, sig_to_tech = {}, {}

    explicit_severity = {}
    if args.level == "technique":
        # Sequential codes from UNMAPPED_CODE+1, severity in a side table --
        # no digit-count constraint, so the low tier keeps all 18 techniques.
        techs = sorted({lab for _, lab in resolved.values()})
        tech_codes = {}
        for offset, lab in enumerate(techs):
            tech_codes[lab] = UNMAPPED_CODE + 1 + offset
        for sig, (tactic, lab) in resolved.items():
            code = tech_codes[lab]
            sig_to_code[sig] = code
            sig_to_tech[sig] = lab
            explicit_severity[code] = severity_of(TACTIC_CODES[tactic][0])
        for lab, code in tech_codes.items():
            code_to_name[code] = f"MitreTechnique.{lab}"
            code_to_symbol[code] = short_symbol(lab)
    elif args.level == "tactic":
        for sig, (tactic, lab) in resolved.items():
            sig_to_code[sig] = TACTIC_CODES[tactic][0]
            sig_to_tech[sig] = lab
    else:
        tech_tier = {lab: severity_of(TACTIC_CODES[tactic][0])
                     for tactic, lab in resolved.values()}
        tech_codes = assign_hybrid_codes(tech_tier)
        for sig, (tactic, lab) in resolved.items():
            if tech_tier[lab] == 1:
                sig_to_code[sig] = TACTIC_CODES[tactic][0]  # low -> tactic
            else:
                sig_to_code[sig] = tech_codes[lab]
            sig_to_tech[sig] = lab
        # Medium/high codes name their technique, not their tactic.
        for lab, code in tech_codes.items():
            code_to_name[code] = f"MitreTechnique.{lab}"
            code_to_symbol[code] = short_symbol(lab)

    if args.unmapped == "catchall":
        for sig in declines + [s for s, _ in no_tactic]:
            sig_to_code[sig] = UNMAPPED_CODE
        code_to_name[UNMAPPED_CODE] = UNMAPPED_NAME
        code_to_symbol[UNMAPPED_CODE] = UNMAPPED_SYMBOL

    counts = {}
    for code in sig_to_code.values():
        counts[code] = counts.get(code, 0) + 1
    used = sorted(counts)

    print(f"level:                  {args.level}")
    print(f"labelled signatures:    {len(labels)}")
    print(f"  mapped:               {len(sig_to_tech)}")
    print(f"  declines:             {len(declines)}  (--unmapped {args.unmapped})")
    print(f"  technique w/o tactic: {len(no_tactic)}")
    by_sev = {1: [], 2: [], 3: []}
    for code in used:
        by_sev[explicit_severity.get(code) or severity_of(code)].append(code)
    print()
    print(f"{len(used)} codes in use:")
    for sev, name in ((1, "low"), (2, "medium"), (3, "high")):
        codes = by_sev[sev]
        total = sum(counts[c] for c in codes)
        print(f"  {name:>6}: {len(codes):3d} codes, {total:4d} signatures")
        for c in codes:
            print(f"          {c:>3}  {code_to_symbol.get(c, '?'):<12s} "
                  f"{code_to_name.get(c, '?'):<34s} {counts[c]:4d}")

    out = args.out or os.path.join(HERE, "mitre_mapping_generated.py")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write('"""GENERATED by signatures/build_mitre_mapping.py -- do not edit.\n\n')
        fh.write(f"unmapped-signature policy: {args.unmapped}\n")
        fh.write(f"{len(sig_to_code)} signatures over {len(used)} tactic codes.\n")
        fh.write("Severity is the digit count of the code, exactly as AIF encodes it,\n")
        fh.write('so no pipeline stage needs changing. See mitre_stages.py.\n"""\n\n')
        fh.write(f"UNMAPPED_POLICY = {args.unmapped!r}\n\n")
        for name, table in (("mitre_signature_to_code", sig_to_code),
                            ("mitre_signature_to_technique", sig_to_tech),
                            ("mitre_code_to_name", code_to_name),
                            ("mitre_small_mapping", code_to_symbol),
                            ("mitre_code_severity", explicit_severity)):
            fh.write(f"{name} = {{\n")
            for k in sorted(table, key=lambda x: (isinstance(x, str), x)):
                fh.write(f"    {k!r}: {table[k]!r},\n")
            fh.write("}\n\n")
        fh.write("rev_mitre_small_mapping = "
                 "{v: k for k, v in mitre_small_mapping.items()}\n")
        if explicit_severity:
            # The technique level cannot encode severity in the digit count
            # (sequential codes are all two digits), so it registers an
            # explicit table that `mitre_stages.severity_of_code` consults.
            fh.write("\nfrom signatures.mitre_stages import register_severity"
                     "  # noqa: E402\n")
            fh.write("register_severity(mitre_code_severity)\n")

    print(f"\nwrote {out}  ({len(sig_to_code)} signatures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
