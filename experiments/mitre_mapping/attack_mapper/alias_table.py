"""
STIX malware/tool alias table -- resolves a rule's text to ATT&CK techniques
via known tool/malware names (e.g. "Havij" -> T1190, "Mimikatz" -> T1003/
T1098/T1558), sourced from the live STIX bundle's `uses` relationships.

Own copy inside this package (the reusable logic originally in
../archive/tiered_approach/tier1_build.py's `build_alias_table`/
`match_signature`, minus that file's own script/CLI bits) so this package
has no imports reaching outside its own tree -- see ../STATUS.md.

Filtered with a minimum alias length, an explicit stoplist for alias/
common-word collisions found during probing ("ping", "page", "photo",
"chaos", "cannon" and others turned out to be real ATT&CK software aliases
that also match unrelated signature text), and a cap on how many techniques
a single alias hit is allowed to carry (a LOLBin-style tool object with a
huge technique fan-out is a weak signal even when the name match itself is
precise).
"""
import re
from typing import Dict, List, Set

MIN_ALIAS_LEN = 5
MAX_TECHNIQUES_PER_ALIAS = 5
STOPLIST = {
    "ping", "page", "photo", "chaos", "calendar", "cannon", "medusa",
    "flame", "cobra", "havex",
}


def external_id(obj: dict):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_alias_table(objs: List[dict]) -> Dict[str, Set[str]]:
    software = {}
    for o in objs:
        if o["type"] not in ("malware", "tool"):
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        names = set()
        if o.get("name"):
            names.add(o["name"])
        for a in o.get("x_mitre_aliases", []) or []:
            names.add(a)
        software[o["id"]] = names

    ap_extid = {o["id"]: external_id(o) for o in objs if o["type"] == "attack-pattern"}

    uses: Dict[str, Set[str]] = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = o.get("source_ref"), o.get("target_ref")
            if src in software and tgt in ap_extid and ap_extid[tgt]:
                uses.setdefault(src, set()).add(ap_extid[tgt])

    alias_table: Dict[str, Set[str]] = {}
    for sid, names in software.items():
        techs = uses.get(sid, set())
        if not techs or len(techs) > MAX_TECHNIQUES_PER_ALIAS:
            continue
        for name in names:
            norm = name.strip().lower()
            if len(norm) < MIN_ALIAS_LEN or norm in STOPLIST:
                continue
            alias_table.setdefault(norm, set()).update(techs)
    return alias_table


def tokens(s: str) -> Set[str]:
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def match_signature(sig: str, alias_table: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    sig_tokens = tokens(sig)
    sig_norm = sig.lower()
    hits = {}
    for alias, techs in alias_table.items():
        if " " in alias:
            if alias in sig_norm:
                hits[alias] = techs
        elif alias in sig_tokens:
            hits[alias] = techs
    return hits
