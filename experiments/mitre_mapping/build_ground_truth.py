"""
Phase 1 step 3: propagate the validated bridge table across the 773 merged
(signature -> MicroAttackStage) ground truth to get
(signature -> MITRE technique/tactic ID(s)) ground truth.

Partitions into three groups (see B4 task + advisor review):
  - technique_scoreable: GT is one or more real technique IDs -> headline top-1/top-3 denominator
  - tactic_only: GT is a tactic ID (TA0xxx) -> scoreable only under "right tactic" metric
  - unmappable: no GT (INIT / NON_MALICIOUS / SERVICE_SPECIFIC) -> excluded, counted, stated

Writes ground_truth_signatures.csv:
  signature, micro_attack_stage, source_container, gt_kind, gt_ids (semicolon-joined), confidence
"""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ground_truth import merge_with_conflicts  # noqa: E402


def main():
    merged, conflicts, containers = merge_with_conflicts()

    with open(os.path.join(HERE, "bridge_table_validated.json"), encoding="utf-8") as fh:
        bridge = json.load(fh)

    rows = []
    counts = {"technique_scoreable": 0, "tactic_only": 0, "unmappable": 0}

    for sig in sorted(merged):
        stage, cname = merged[sig]
        b = bridge[stage.name]
        kind = b["kind"]
        ids = b["resolved_ids"]

        if kind == "technique" and ids:
            gt_kind = "technique_scoreable"
        elif kind == "tactic" and ids:
            gt_kind = "tactic_only"
        else:
            gt_kind = "unmappable"

        counts[gt_kind] += 1
        rows.append({
            "signature": sig,
            "micro_attack_stage": stage.name,
            "source_container": cname,
            "gt_kind": gt_kind,
            "gt_ids": ";".join(ids),
            "confidence": b["confidence"],
        })

    out_path = os.path.join(HERE, "ground_truth_signatures.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["signature", "micro_attack_stage", "source_container",
                                            "gt_kind", "gt_ids", "confidence"])
        w.writeheader()
        w.writerows(rows)

    print(f"Total signatures: {len(rows)}")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    print(f"\nWrote {out_path}")

    # low-confidence rows worth flagging in the report
    shaky = [r for r in rows if r["confidence"] in ("ambiguous", "needs_review")]
    print(f"\n{len(shaky)} rows carry a shaky (ambiguous/needs_review) bridge-table confidence "
          f"-- scored results for these should be trusted less.")

    return rows, counts


if __name__ == "__main__":
    main()
