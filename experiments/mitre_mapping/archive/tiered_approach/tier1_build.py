"""
Tier 1: entity extraction -> ATT&CK object lookup.

Build an alias table from STIX malware/tool objects (name + x_mitre_aliases)
and match against our 773 signature strings. Malware/tool names are usually
rare tokens and high-precision -- but a handful of ATT&CK aliases collide
with common English words ("ping", "page", "photo", "chaos", "cannon" all
showed up as real aliases during probing and produced garbage matches
against unrelated signatures). Filtered here with:
  - a minimum alias length
  - an explicit stoplist of the common-word collisions found during probing
  - a cap on how many techniques a single alias hit is allowed to carry
    (a LOLBin-style tool object with a huge technique fan-out is a weak
    signal even when the name match itself is precise)

Usage: python tier1_build.py
Requires ../enterprise-attack.json (fetch via ../fetch_techniques.py).
"""
import csv
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STIX_PATH = os.path.join(ROOT, "enterprise-attack.json")
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
OUT_PATH = os.path.join(HERE, "tier1_hits.csv")

MIN_ALIAS_LEN = 5
MAX_TECHNIQUES_PER_ALIAS = 5
# Common-English-word aliases found during probing that produce false
# positives against unrelated signature text -- not malicious, just noise.
STOPLIST = {
    "ping", "page", "photo", "chaos", "calendar", "cannon", "medusa",
    "flame", "cobra", "havex",
}


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_alias_table(objs):
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

    uses = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = o.get("source_ref"), o.get("target_ref")
            if src in software and tgt in ap_extid and ap_extid[tgt]:
                uses.setdefault(src, set()).add(ap_extid[tgt])

    alias_table = {}
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


def tokens(s):
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def match_signature(sig, alias_table):
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


def main():
    with open(STIX_PATH, encoding="utf-8") as fh:
        objs = json.load(fh)["objects"]
    alias_table = build_alias_table(objs)
    print(f"alias table size (post-filter): {len(alias_table)}")

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]

    rows = []
    for sig in sigs:
        hits = match_signature(sig, alias_table)
        if not hits:
            continue
        all_techs = set()
        for techs in hits.values():
            all_techs |= techs
        rows.append((sig, ";".join(sorted(hits.keys())), ";".join(sorted(all_techs))))

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "matched_aliases", "technique_ids"])
        w.writerows(rows)

    print(f"Tier 1 alias hits on our 773 signatures: {len(rows)}")
    for sig, aliases, techs in rows:
        print(f" - {sig} | {aliases} -> {techs}")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
