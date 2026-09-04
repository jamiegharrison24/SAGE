"""
Phase 1 ground truth: merge the four hand-labelled signature->MicroAttackStage
containers in signatures/alert_signatures.py, resolve conflicts by priority
(ccdc_combined > usual_mapping > unknown_mapping > attack_stage_mapping), and
propagate the B4 bridge table (see bridge_table.py) to get
signature -> MITRE ATT&CK technique/tactic ground truth.

Does not touch the production pipeline. Standalone, self-contained under
experiments/mitre_mapping/.
"""
import csv
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from signatures.attack_stages import MicroAttackStage  # noqa: E402
import signatures.alert_signatures as sig_module  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Priority order, highest first, per B4 task instructions.
CONTAINER_PRIORITY = ["ccdc_combined", "usual_mapping", "unknown_mapping", "attack_stage_mapping"]


def _attack_stage_mapping_inverted():
    """attack_stage_mapping is {MicroAttackStage: [signature, ...]} -- invert to
    {signature: MicroAttackStage}, last-list-entry-wins on internal dupes (none
    expected, but be explicit rather than silently overwrite in an unnoticed order)."""
    inverted = {}
    for stage, sig_list in sig_module.attack_stage_mapping.items():
        for s in sig_list:
            inverted[s] = stage
    return inverted


def load_named_containers():
    return {
        "ccdc_combined": dict(sig_module.ccdc_combined),
        "usual_mapping": dict(sig_module.usual_mapping),
        "unknown_mapping": dict(sig_module.unknown_mapping),
        "attack_stage_mapping": _attack_stage_mapping_inverted(),
    }


def merge_with_conflicts():
    """Returns (merged: {sig: (MicroAttackStage, winning_container)},
    conflicts: {sig: {container: MicroAttackStage}})."""
    containers = load_named_containers()

    per_sig_labels = defaultdict(dict)  # sig -> {container: stage}
    for cname in CONTAINER_PRIORITY:
        for sig, stage in containers[cname].items():
            per_sig_labels[sig][cname] = stage

    conflicts = {}
    merged = {}
    for sig, labels in per_sig_labels.items():
        distinct_stages = set(labels.values())
        if len(distinct_stages) > 1:
            conflicts[sig] = labels
        # priority order: pick from the highest-priority container that has this sig
        for cname in CONTAINER_PRIORITY:
            if cname in labels:
                merged[sig] = (labels[cname], cname)
                break

    return merged, conflicts, containers


def main():
    merged, conflicts, containers = merge_with_conflicts()

    print("Container sizes (raw, before merge):")
    for cname in CONTAINER_PRIORITY:
        print(f"  {cname:<22} {len(containers[cname])}")

    print(f"\nMerged unique signatures: {len(merged)}")
    print(f"Signatures with a conflicting label across containers: {len(conflicts)}")

    conflicts_path = os.path.join(HERE, "conflicts.csv")
    with open(conflicts_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "winning_container", "winning_stage"] + CONTAINER_PRIORITY)
        for sig in sorted(conflicts):
            winning_stage, winning_container = merged[sig]
            row = [sig, winning_container, winning_stage.name]
            for cname in CONTAINER_PRIORITY:
                stage = conflicts[sig].get(cname)
                row.append(stage.name if stage else "")
            w.writerow(row)
    print(f"Wrote conflict detail to {conflicts_path}")

    merged_path = os.path.join(HERE, "merged_ground_truth_stage.csv")
    with open(merged_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "micro_attack_stage", "source_container"])
        for sig in sorted(merged):
            stage, cname = merged[sig]
            w.writerow([sig, stage.name, cname])
    print(f"Wrote merged ground truth (stage-level) to {merged_path}")

    return merged, conflicts


if __name__ == "__main__":
    main()
