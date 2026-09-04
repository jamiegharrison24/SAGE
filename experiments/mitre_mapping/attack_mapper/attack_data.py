"""
Shared helpers for reading the local STIX Enterprise ATT&CK bundle
(./data/enterprise-attack.json, gitignored -- large, re-downloadable; see
../archive/fetch_techniques.py for how it was originally fetched).

Own copy inside this package (originally ../archive/attack_data.py) so this
package has no imports reaching outside its own tree -- see ../STATUS.md.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_PATH = os.path.join(HERE, "data", "enterprise-attack.json")


def load_bundle():
    with open(BUNDLE_PATH, encoding="utf-8") as fh:
        return json.load(fh)["objects"]


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_techniques(objs=None, include_deprecated_revoked=False):
    """Returns {technique_id: attack_pattern_object} for non-deprecated,
    non-revoked attack-patterns (both techniques and sub-techniques)."""
    objs = objs if objs is not None else load_bundle()
    out = {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        if not include_deprecated_revoked and (o.get("revoked") or o.get("x_mitre_deprecated")):
            continue
        tid = external_id(o)
        if tid:
            out[tid] = o
    return out


def load_tactics(objs=None):
    """Returns {shortname: tactic_id} e.g. {'defense-evasion': 'TA0005'}."""
    objs = objs if objs is not None else load_bundle()
    out = {}
    for o in objs:
        if o["type"] != "x-mitre-tactic":
            continue
        tid = external_id(o)
        shortname = o.get("x_mitre_shortname")
        if tid and shortname:
            out[shortname] = tid
    return out


def technique_tactics(attack_pattern_obj, shortname_to_taid):
    """Tactic IDs (TA0xxx) a technique belongs to, from its kill_chain_phases."""
    tas = []
    for phase in attack_pattern_obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        taid = shortname_to_taid.get(phase.get("phase_name"))
        if taid:
            tas.append(taid)
    return tas


def sub_techniques_of(parent_id, techniques):
    """All technique IDs 'T1566.001' etc that start with 'parent_id.'"""
    return sorted(t for t in techniques if t.startswith(parent_id + "."))


def expand_range(start_id, end_id, techniques):
    """Resolve a 'T1566.001'..'T1566.003' style range (same parent) to the set
    of sub-technique IDs that actually exist in the live corpus, inclusive."""
    parent = start_id.split(".")[0]
    assert end_id.split(".")[0] == parent, (start_id, end_id)
    start_n = int(start_id.split(".")[1])
    end_n = int(end_id.split(".")[1])
    result = []
    for n in range(start_n, end_n + 1):
        cand = f"{parent}.{n:03d}"
        if cand in techniques:
            result.append(cand)
    return result
