"""
Validation harness for the attack_mapper pipeline against the hand-audited
sample (`data/hand_audit_sample*.csv`), using the *same* scoring convention
as the original tiered-approach comparison (top-1 vs the audit's
`proposed_technique` column, non-ambiguous rows only -- see
`archive/tiered_approach/compare_tier2_vs_audit.py`) so the result is
directly comparable to that baseline (34.2% top-1, 27/79 scoreable rows).

Note up front: the user's brief asks for validation against a 200+-rule
labeled regression set. This repo currently has 100 hand-audited rows
(79 scoreable) across the three hand_audit_sample*.csv batches -- see
findings.md for the explicit gap. This harness scores what exists; it does
not claim the 200+ bar is met.

Usage:
    python validate.py                # LLM-off baseline (default, no setup needed)
    python validate.py --llm ollama   # also exercise Layer D via a local Ollama
                                       # server -- see attack_mapper/LLM_SETUP.md.
                                       # Writes validation_report_llm.md, separate
                                       # from the committed LLM-off baseline, so the
                                       # two are diffable rather than one overwriting
                                       # the other.
Requires the attack_mapper package (same directory) and the STIX bundle at
attack_mapper/data/enterprise-attack.json.
"""
import argparse
import csv
import glob
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "attack_mapper", "data")
sys.path.insert(0, HERE)

from attack_mapper.pipeline import AttackMapperPipeline  # noqa: E402
from attack_mapper.llm_client import ollama_client  # noqa: E402


def parse_proposed(cell):
    """None for ambiguous/non-malicious rows (excluded from strict scoring),
    else the set of acceptable technique IDs. Same convention as
    archive/tiered_approach/compare_tier2_vs_audit.py's function of the same
    name, kept in sync deliberately so results stay comparable."""
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    ids = re.findall(r"T\d{4}(?:\.\d{3})?", cell)
    return set(ids) if ids else None


def load_audit_rows():
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA_DIR, "hand_audit_sample*.csv"))):
        with open(fn, encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--llm", choices=["ollama"], default=None,
        help="Exercise Layer D via a local Ollama server (see attack_mapper/LLM_SETUP.md). "
             "Default: no LLM, matching every number reported in findings.md so far.",
    )
    parser.add_argument(
        "--llm-model", default="llama3.2:3b",
        help="Ollama model tag (with --llm ollama). Default is the small (~2GB) model -- "
             "the only one actually scored so far; see attack_mapper/LLM_SETUP.md for why "
             "llama3.1:8b repeatedly OOM-killed on a 16GB machine before finishing.",
    )
    args = parser.parse_args()

    out_path = os.path.join(HERE, "validation_report_llm.md" if args.llm else "validation_report.md")

    llm_client = ollama_client(model=args.llm_model) if args.llm == "ollama" else None
    if llm_client:
        print(f"LLM reasoning layer: Ollama, model={args.llm_model}")

    rows = load_audit_rows()
    pipeline = AttackMapperPipeline(llm_client=llm_client)

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
        f"- LLM reasoning layer (Layer D): {'Ollama ' + args.llm_model if llm_client else 'off (NullLLMClient)'}",
        f"- matched audit rows: **{len(rows)}**",
        f"- scoreable (non-ambiguous) rows: **{scoreable}**",
        (f"- top-1 correct vs. hand-audit proposed technique: "
         f"**{correct}/{scoreable} = {correct / scoreable:.1%}**") if scoreable else "- scoreable: 0",
        (f"- flagged for human review: {review_required_count}/{len(rows)} "
         f"({review_required_count / len(rows):.1%})") if rows else "",
        f"- source breakdown (top-1 mapping's source): {source_counts}",
        f"- wall time: {elapsed:.1f}s for {len(rows)} rows\n",
        "**Baseline for comparison** (`archive/tiered_approach/tier2_vs_audit_findings.md`, "
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

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Wrote {out_path}")
    if scoreable:
        print(f"top-1 vs hand-audit: {correct}/{scoreable} = {correct / scoreable:.1%}")
    print(f"human review required: {review_required_count}/{len(rows)}")
    print(f"source breakdown: {source_counts}")


if __name__ == "__main__":
    main()
