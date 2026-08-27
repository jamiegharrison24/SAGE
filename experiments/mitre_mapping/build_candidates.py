"""
Phase 2: scope the technique candidate set to those plausibly observable from
a network IDS alert.

The bundle in enterprise-attack.json uses ATT&CK's newer STIX shape (Oct 2025
data-source-v2 restructure): there is no x_mitre_data_sources field on
attack-pattern objects any more, AND x-mitre-data-component objects carry no
x_mitre_data_source_ref back to their parent x-mitre-data-source (checked
live -- the field is present in the schema but null on every one of the 109
components in this bundle; the old 38-category "Network Traffic" / "DNS" /
etc. data-source list is present as objects but is no longer joinable to
techniques at all).

What *is* still joinable, and is what actually gates each technique's
"detects" relationship, is the 109 x-mitre-data-component objects themselves:

  attack-pattern <--(detects)-- x-mitre-detection-strategy
                                    --x_mitre_analytic_refs--> x-mitre-analytic
                                         --x_mitre_log_source_references[].x_mitre_data_component_ref-->
                                    x-mitre-data-component (.name)

So we use the data-component name (still a small finite STIX-sourced
vocabulary -- 109 fixed values, not free text) as the classification unit
instead of the now-orphaned 38-category data-source name. Each component is
classified by hand, category by category, as plausibly Suricata-observable
or not (checking description text for the ambiguous ones), then a technique
is kept if it has >=1 network-plausible data component.

Being inclusive on ambiguous categories per the task: a wrongly-excluded
technique can never be a correct answer, so over-inclusion costs less than
under-inclusion.
"""
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attack_data  # noqa: E402

# Category-by-category call over the 109 data-component names. A Suricata
# network IDS alert can plausibly be evidence for these. Kept inclusive on
# anything with a plausible network angle (see task instructions); checked
# description text for the non-obvious ones (Response Content/Metadata are
# internet-scan network captures -- include; Malware Content/Metadata are
# static payload/repo analysis -- exclude; Social Media is externally
# observed platform activity, not Suricata-visible -- exclude).
NETWORK_PLAUSIBLE_DATA_COMPONENTS = {
    "Active DNS",
    "Passive DNS",
    "Domain Registration",
    "Network Connection Creation",
    "Network Share Access",
    "Network Traffic Content",
    "Network Traffic Flow",
    "Certificate Registration",
    "Firewall Disable",
    "Firewall Enumeration",
    "Firewall Metadata",
    "Firewall Rule Modification",
    "Cloud Service Disable",
    "Cloud Service Enumeration",
    "Cloud Service Metadata",
    "Cloud Service Modification",
    "Response Content",
    "Response Metadata",
}


def build_technique_datacomponents():
    objs = attack_data.load_bundle()
    techniques = attack_data.load_techniques(objs)

    dc_id_to_name = {o["id"]: o["name"] for o in objs if o["type"] == "x-mitre-data-component"}

    analytic_to_dc = defaultdict(set)
    for o in objs:
        if o["type"] == "x-mitre-analytic":
            for ref in o.get("x_mitre_log_source_references", []):
                dc_ref = ref.get("x_mitre_data_component_ref")
                if dc_ref:
                    analytic_to_dc[o["id"]].add(dc_ref)

    detstrat_to_analytics = defaultdict(set)
    for o in objs:
        if o["type"] == "x-mitre-detection-strategy":
            for ref in o.get("x_mitre_analytic_refs", []):
                detstrat_to_analytics[o["id"]].add(ref)

    ap_to_dc_names = defaultdict(set)
    for r in objs:
        if r["type"] != "relationship" or r["relationship_type"] != "detects":
            continue
        detstrat_id, ap_id = r["source_ref"], r["target_ref"]
        for analytic_id in detstrat_to_analytics.get(detstrat_id, ()):
            for dc_id in analytic_to_dc.get(analytic_id, ()):
                dc_name = dc_id_to_name.get(dc_id)
                if dc_name:
                    ap_to_dc_names[ap_id].add(dc_name)

    # id-keyed (external technique id) view for the rest of the pipeline
    tid_to_dc_names = {}
    for tid, ap_obj in techniques.items():
        tid_to_dc_names[tid] = ap_to_dc_names.get(ap_obj["id"], set())

    all_dc_names = sorted({n for s in tid_to_dc_names.values() for n in s})
    return techniques, tid_to_dc_names, all_dc_names


def main():
    techniques, tid_to_dc, all_dc_names = build_technique_datacomponents()

    unclassified = set(all_dc_names) - NETWORK_PLAUSIBLE_DATA_COMPONENTS
    print(f"{len(all_dc_names)} distinct data-component categories are actually linked to "
          f"techniques via 'detects' in this bundle; {len(unclassified)} of them were judged "
          f"not network-plausible (host/process/file/etc.)")

    filtered = {
        tid for tid, dcs in tid_to_dc.items()
        if dcs & NETWORK_PLAUSIBLE_DATA_COMPONENTS
    }

    print(f"Full technique corpus (non-deprecated/revoked): {len(techniques)}")
    print(f"Network-observable data-component categories used: {sorted(NETWORK_PLAUSIBLE_DATA_COMPONENTS)}")
    print(f"Filtered candidate set (>=1 network-plausible data component): {len(filtered)}")
    no_dc_at_all = sum(1 for dcs in tid_to_dc.values() if not dcs)
    print(f"(of the full corpus, {no_dc_at_all} techniques have NO detection-strategy-linked "
          f"data component at all in this bundle -- these are excluded from filtered by construction)")

    out = {
        "full_count": len(techniques),
        "filtered_count": len(filtered),
        "network_plausible_data_components": sorted(NETWORK_PLAUSIBLE_DATA_COMPONENTS),
        "all_data_components_seen": all_dc_names,
        "filtered_ids": sorted(filtered),
    }
    out_path = os.path.join(HERE, "candidate_techniques.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nWrote {out_path}")
    return out


if __name__ == "__main__":
    main()
