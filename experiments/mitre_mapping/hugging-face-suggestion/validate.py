"""
Validation harness for the attack_mapper pipeline against the hand-audited
sample (`../tiered_approach/hand_audit_sample*.csv`), using the *same*
scoring convention as `../tiered_approach/compare_tier2_vs_audit.py` (top-1
vs the audit's `proposed_technique` column, non-ambiguous rows only) so the
result is directly comparable to the existing tiered-approach baseline
(34.2% top-1, 27/79 scoreable rows).

Note up front: the user's brief asks for validation against a 200+-rule
labeled regression set. This repo currently has 100 hand-audited rows
(79 scoreable) across the three hand_audit_sample*.csv batches -- see
../findings.md for the explicit gap. This harness scores what exists; it
does not claim the 200+ bar is met.

Usage: python validate.py
Requires the attack_mapper package (same directory) and the STIX bundle at
../enterprise-attack.json.
"""
import csv
import glob
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TIERED_DIR = os.path.normpath(os.path.join(HERE, "..", "tiered_approach"))
sys.path.insert(0, TIERED_DIR)
sys.path.insert(0, HERE)

from compare_tier2_vs_audit import parse_proposed  # noqa: E402
from attack_mapper.pipeline import AttackMapperPipeline  # noqa: E402

OUT_PATH = os.path.join(HERE, "validation_report.md")


def load_audit_rows():
    rows = []
    for fn in sorted(glob.glob(os.path.join(TIERED_DIR, "hand_audit_sample*.csv"))):
        with open(fn, encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


def main():
    rows = load_audit_rows()
    pipeline = AttackMapperPipeline()

    scoreable = correct = 0
    source_counts = {}
    review_required_count = 0
    detail = []

    t0 = time.monotonic()
    for row in rows:
        sig = row["signature"]
        ids = parse_proposed(row["proposed_technique"])
        mapped = pipeline.process_rule(sig, micro_attack_stage=row.get("micro_attack_stage") or None)

        top = mapped.mappings[0] if mapped.mappings else None
        top_id = top.technique_id if top else None
        source = top.source if top else "none"
        source_counts[source] = source_counts.get(source, 0) + 1
        if mapped.human_review_required:
            review_required_count += 1

        verdict = "SKIPPED"
        if ids is not None:
            scoreable += 1
            hit = top_id in ids if top_id else False
            correct += hit
            verdict = "HIT" if hit else "MISS"

        detail.append((
            sig, row["proposed_technique"], top_id, source,
            f"{top.confidence:.2f}" if top else "-", verdict,
        ))
    elapsed = time.monotonic() - t0

    lines = [
        "# attack_mapper vs. hand-audited sample\n",
        f"- matched audit rows: **{len(rows)}**",
        f"- scoreable (non-ambiguous) rows: **{scoreable}**",
        (f"- top-1 correct vs. hand-audit proposed technique: "
         f"**{correct}/{scoreable} = {correct / scoreable:.1%}**") if scoreable else "- scoreable: 0",
        (f"- flagged for human review: {review_required_count}/{len(rows)} "
         f"({review_required_count / len(rows):.1%})") if rows else "",
        f"- source breakdown (top-1 mapping's source): {source_counts}",
        f"- wall time: {elapsed:.1f}s for {len(rows)} rows\n",
        "**Baseline for comparison** (`../tiered_approach/tier2_vs_audit_findings.md`, "
        "TF-IDF classifier trained on 26,644-row ET-labeled corpus): "
        "27/79 = 34.2% top-1.\n",
        "**Coverage caveat**: the brief asks for a 200+-rule labeled regression set; "
        f"this harness only has {len(rows)} hand-audited rows ({scoreable} scoreable) "
        "to draw on. Treat the number above as directional, not a satisfied "
        "validation bar.\n",
        "## Miss / skip rows\n",
        "| proposed | mapper top-1 (source, conf) | verdict | signature |",
        "|---|---|---|---|",
    ]
    for sig, proposed, top_id, source, conf, verdict in detail:
        if verdict != "HIT":
            lines.append(f"| {proposed} | {top_id} ({source}, {conf}) | {verdict} | {sig} |")
    lines += ["\n## Hit rows\n", "| proposed | mapper top-1 (source, conf) | signature |", "|---|---|---|"]
    for sig, proposed, top_id, source, conf, verdict in detail:
        if verdict == "HIT":
            lines.append(f"| {proposed} | {top_id} ({source}, {conf}) | {sig} |")

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Wrote {OUT_PATH}")
    if scoreable:
        print(f"top-1 vs hand-audit: {correct}/{scoreable} = {correct / scoreable:.1%}")
    print(f"human review required: {review_required_count}/{len(rows)}")
    print(f"source breakdown: {source_counts}")


if __name__ == "__main__":
    main()
