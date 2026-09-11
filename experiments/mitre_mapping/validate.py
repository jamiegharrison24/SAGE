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

# Both are gitignored (large, re-downloadable), so a fresh clone has neither.
# Without emerging-all.rules the Suricata extractor sees only signature titles,
# never rule bodies, so ET's own mitre_technique_id metadata is never harvested
# and the `declared` source (11 rows at 81.8% precision) silently vanishes --
# scoring 43.8% instead of 53.8% while looking like a valid baseline run.
REQUIRED_DATA = {
    "emerging-all.rules": (
        "python -c \"import urllib.request as u; u.urlretrieve("
        "'https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules', "
        "'attack_mapper/data/emerging-all.rules')\""
    ),
    "enterprise-attack.json": (
        "python -c \"import urllib.request as u; u.urlretrieve("
        "'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
        "enterprise-attack.json', 'attack_mapper/data/enterprise-attack.json')\""
    ),
}


def check_required_data():
    missing = [(n, cmd) for n, cmd in REQUIRED_DATA.items()
               if not os.path.exists(os.path.join(DATA_DIR, n))]
    if not missing:
        return
    print("ERROR: required data files are missing from attack_mapper/data/.", file=sys.stderr)
    print("These are gitignored (large, re-downloadable), so a fresh clone lacks them.", file=sys.stderr)
    print("Scoring without them produces a silently degraded number, not a baseline.\n", file=sys.stderr)
    for name, cmd in missing:
        print(f"  missing: {name}\n    fetch:  {cmd}\n", file=sys.stderr)
    sys.exit(1)


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


def load_audit_rows(include_v2=True):
    """Two label sets, kept distinguishable on purpose.

    `hand_audit_sample*.csv` is the original 100-row set. `labeled_set_v2.csv`
    is the blind-labeled expansion (see `label_queue/CONVENTION.md`), whose
    rows are `model_proposed` until a human fills in `reviewer_verdict`.
    Every row carries `_origin` and `label_source` so the report can state the
    split rather than presenting 500 machine labels as "hand-audited".
    """
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA_DIR, "hand_audit_sample*.csv"))):
        with open(fn, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                r["_origin"] = "hand_audit"
                r.setdefault("label_source", "hand_audit")
                rows.append(r)
    v2 = os.path.join(DATA_DIR, "labeled_set_v2.csv")
    if include_v2 and os.path.exists(v2):
        with open(v2, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                r["_origin"] = "v2_blind"
                rows.append(r)
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
    parser.add_argument(
        "--hand-audit-only", action="store_true",
        help="Score only the original 100 hand-audited rows, excluding the blind-labeled "
             "expansion in labeled_set_v2.csv. Use this to reproduce the historical "
             "numbers in findings.md exactly.",
    )
    args = parser.parse_args()

    check_required_data()

    out_path = os.path.join(HERE, "validation_report_llm.md" if args.llm else "validation_report.md")

    llm_client = ollama_client(model=args.llm_model) if args.llm == "ollama" else None
    if llm_client:
        print(f"LLM reasoning layer: Ollama, model={args.llm_model}")

    rows = load_audit_rows(include_v2=not args.hand_audit_only)
    pipeline = AttackMapperPipeline(llm_client=llm_client)
    origin_stats = {}
    verified_stats = {}

    scoreable = correct = 0
    source_counts = {}
    review_required_count = 0
    body_matched_count = 0
    per_technique = {}
    predicted_counts = {}
    tactic_only = 0
    source_acc = {}
    knn_corpus_acc = {}
    detail = []

    t0 = time.monotonic()
    for row in rows:
        sig = row["signature"]
        ids = parse_proposed(row["proposed_technique"])
        mapped = pipeline.process_rule(sig)

        top = mapped.mappings[0] if mapped.mappings else None
        top_id = top.technique_id if top else None
        source = top.source if top else "none"
        source_counts[source] = source_counts.get(source, 0) + 1
        if mapped.human_review_required:
            review_required_count += 1
        if mapped.rule.body_matched:
            body_matched_count += 1

        # Tactic-only rows (TA####) can never match parse_proposed's T\d{4}, so
        # they are skipped. Counted explicitly because a silent skip is how a
        # scoreable-row count quietly drifts from the labeled-row count.
        if row["proposed_technique"].strip().startswith("TA"):
            tactic_only += 1

        verdict = "SKIPPED"
        if ids is not None:
            scoreable += 1
            hit = top_id in ids if top_id else False
            correct += hit
            verdict = "HIT" if hit else "MISS"
            # Bucket by true label so macro-average can be computed below.
            key = "/".join(sorted(ids))
            bucket = per_technique.setdefault(key, [0, 0])
            bucket[0] += hit
            bucket[1] += 1
            ob = origin_stats.setdefault(row.get("_origin", "?"), [0, 0])
            ob[0] += hit
            ob[1] += 1
            is_confirmed = (row.get("label_source") in ("hand_audit", "human_confirmed")
                            or row.get("reviewer_verdict", "").strip())
            vb = verified_stats.setdefault("confirmed" if is_confirmed else "pending", [0, 0])
            vb[0] += hit
            vb[1] += 1
            sb = source_acc.setdefault(source, [0, 0])
            sb[0] += hit
            sb[1] += 1
            # Which corpus supplied the winning neighbour, for knn_corpus rows.
            # Adding corpus rows shifts the IDF denominator for *every*
            # technique, so the headline can move even on rows where no
            # new-corpus row is ever retrieved -- this attributes the answer
            # rather than assuming the new data caused the delta.
            if source == "knn_corpus" and top:
                m = re.search(r"closest \[(\w+)\]", " ".join(top.evidence))
                if m:
                    kb = knn_corpus_acc.setdefault(m.group(1), [0, 0])
                    kb[0] += hit
                    kb[1] += 1
            if top_id:
                predicted_counts[top_id] = predicted_counts.get(top_id, 0) + 1

        detail.append((
            sig, row["proposed_technique"], top_id, source,
            f"{top.confidence:.2f}" if top else "-", verdict,
        ))
    elapsed = time.monotonic() - t0

    # Macro-average = mean per-true-label accuracy, so every technique counts
    # once regardless of how many rows carry it. Micro-average alone rewards
    # collapsing to the modal class: this sample is 28% T1190, so a mapper that
    # answered T1190 unconditionally would score ~28% micro but ~2% macro. See
    # findings.md's qwen2.5:7b-instruct section for exactly that failure mode
    # passing unnoticed under micro-only scoring.
    macro = (sum(h / n for h, n in per_technique.values()) / len(per_technique)
             if per_technique else 0.0)
    top_pred, top_pred_n = max(predicted_counts.items(), key=lambda kv: kv[1], default=("-", 0))
    pred_share = top_pred_n / scoreable if scoreable else 0.0
    confirmed_n = sum(1 for r in rows
                      if r.get("label_source") in ("hand_audit", "human_confirmed")
                      or r.get("reviewer_verdict", "").strip())

    lines = [
        "# attack_mapper vs. hand-audited sample\n",
        f"- LLM reasoning layer (Layer D): {'Ollama ' + args.llm_model if llm_client else 'off (NullLLMClient)'}",
        f"- matched audit rows: **{len(rows)}**",
        f"- scoreable (non-ambiguous) rows: **{scoreable}**",
        (f"- excluded: {len(rows) - scoreable} rows -- of which {tactic_only} are tactic-only "
         "(`TA####`, unhittable by a technique-predicting pipeline, skipped by design -- see "
         "`label_queue/CONVENTION.md`), the rest ambiguous or non-malicious"),
        (f"- top-1 correct vs. hand-audit proposed technique (micro): "
         f"**{correct}/{scoreable} = {correct / scoreable:.1%}**") if scoreable else "- scoreable: 0",
        (f"- **macro-average** (mean per-technique accuracy, {len(per_technique)} distinct "
         f"true labels): **{macro:.1%}**") if per_technique else "",
        (f"- most-predicted technique: {top_pred} on {top_pred_n}/{scoreable} scoreable rows "
         f"({pred_share:.1%}) -- a large gap between micro and macro, or a share well above "
         "the true base rate, indicates collapse toward the modal class rather than "
         "per-rule reasoning") if scoreable else "",
        (f"- flagged for human review: {review_required_count}/{len(rows)} "
         f"({review_required_count / len(rows):.1%})") if rows else "",
        f"- source breakdown (top-1 mapping's source): {source_counts}",
        (f"- kNN retrieval pool (neighbours returned, by corpus): "
         f"{getattr(pipeline.knn, 'neighbour_source_counts', {})} -- a corpus contributing rows "
         "but never winning a top-k slot did not affect retrieval; any accuracy delta in that "
         "case came from the IDF denominator shifting, not new signal") if pipeline.knn else "",
        ("- knn_corpus top-1 accuracy by winning corpus: " + ", ".join(
            f"{k} {h}/{n} = {h / n:.1%}" for k, (h, n) in sorted(knn_corpus_acc.items()))
         ) if knn_corpus_acc else "",
        (f"- label provenance: {confirmed_n} human-confirmed, {len(rows) - confirmed_n} "
         "model-proposed/unconfirmed"),
        ("- accuracy on reviewer-confirmed rows so far: " + ", ".join(
            f"{k} {h}/{n} = {h / n:.1%}" for k, (h, n) in sorted(verified_stats.items(), reverse=True))
         + " -- confirmed is the only number that reflects real ground truth; pending "
           "will move as review continues") if len(verified_stats) > 1 else "",
        ("- accuracy by label set: " + ", ".join(
            f"{k} {h}/{n} = {h / n:.1%}" for k, (h, n) in sorted(origin_stats.items()))
         + " -- a gap between the two has three candidate causes and this line alone "
           "does not distinguish them: (a) the blind set is genuinely harder (more distinct "
           "true labels, longer tail), (b) the original set was optimistic because its labels "
           "were derived through the same bridge table the pipeline's dominant source uses, "
           "or (c) labeling drift in the expansion. Compare macro vs micro for (a), the "
           "bridge-agreement rates for (b), and the re-label consistency check for (c)")
        if len(origin_stats) > 1 else "",
        (f"- ET rule body matched (not just the title): {body_matched_count}/{len(rows)} "
         f"({body_matched_count / len(rows):.1%}) -- near 0% means "
         "`attack_mapper/data/emerging-all.rules` is stale or absent and the "
         "`declared` source cannot fire; the run is degraded, not a baseline") if rows else "",
        f"- wall time: {elapsed:.1f}s for {len(rows)} rows\n",
        "**Baseline for comparison** (`archive/tiered_approach/tier2_vs_audit_findings.md`, "
        "TF-IDF classifier trained on 26,644-row ET-labeled corpus): "
        "27/79 = 34.2% top-1.\n",
        "**Coverage caveat**: the brief asks for a 200+-rule labeled regression set. "
        f"This harness scores {len(rows)} rows ({scoreable} scoreable), of which "
        f"**{confirmed_n} are human-confirmed** and {len(rows) - confirmed_n} are "
        "model-proposed labels awaiting review (`label_source`, and the empty "
        "`reviewer_verdict` column, mark which is which -- see "
        "`label_queue/CONVENTION.md`). Row count alone does not satisfy the bar: "
        "an unreviewed label is a hypothesis, not ground truth.\n",
        "## Accuracy by candidate source\n",
        "Which layer of `reasoner.py`'s priority cascade actually produced the top-1 "
        "answer, and how often it was right. A source with high volume and low accuracy "
        "is where the pipeline is losing.\n",
        "| source | hits / scoreable rows | accuracy |",
        "|---|---:|---:|",
    ] + [
        f"| `{k}` | {h}/{n} | {h / n:.1%} |"
        for k, (h, n) in sorted(source_acc.items(), key=lambda kv: -kv[1][1])
    ] + [
        "\n## Miss / skip rows\n",
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
        print(f"top-1 vs hand-audit (micro): {correct}/{scoreable} = {correct / scoreable:.1%}")
        print(f"macro-average ({len(per_technique)} distinct true labels): {macro:.1%}")
        print(f"most-predicted: {top_pred} on {top_pred_n}/{scoreable} rows ({pred_share:.1%})")
    print(f"ET rule body matched: {body_matched_count}/{len(rows)}")
    print(f"human review required: {review_required_count}/{len(rows)}")
    print(f"source breakdown: {source_counts}")
    if pipeline.knn:
        print(f"kNN retrieval pool by corpus: {pipeline.knn.neighbour_source_counts}")
    if knn_corpus_acc:
        print("knn_corpus accuracy by winning corpus: " + ", ".join(
            f"{k} {h}/{n} = {h / n:.1%}" for k, (h, n) in sorted(knn_corpus_acc.items())))


if __name__ == "__main__":
    main()
