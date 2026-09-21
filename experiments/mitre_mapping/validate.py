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

from attack_mapper import entity_tagger  # noqa: E402
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
    parser.add_argument(
        "--entity-tagging", nargs="?", const=entity_tagger.DEFAULT_MERGE_RULE,
        default=None, choices=list(entity_tagger.MERGE_RULES),
        help="Enable entity-aware normalisation (plan §5 Step 2) with the given merge "
             "rule. Needs the precomputed spans artifact -- build it with "
             "`python -m attack_mapper.entity_ner.build_spans` -- except for "
             "'gazetteer_only', which needs none. Default: off, matching every "
             "number in findings.md so far.",
    )
    parser.add_argument(
        "--ner-backend", default=entity_tagger.DEFAULT_NER_BACKEND,
        choices=list(entity_tagger.NER_BACKENDS),
        help="Which NER model backs --entity-tagging. 'gliner' (effort 13, "
             "the committed baseline) or 'securemodernbert' (cyber-domain- "
             "trained, per entity_ner/comparison_findings.md's addendum -- "
             "needs its own spans artifact: `build_spans.py --backend "
             "securemodernbert`). Meaningless without --entity-tagging.",
    )
    parser.add_argument(
        "--typed-markers", action=argparse.BooleanOptionalAction, default=None,
        help="Effort 17: append a per-type sentinel (qqe_productqq, "
             "qqe_orgqq, ...) instead of one generic <ENTITY>. Needs a spans "
             "artifact built with per-span types (`build_spans.py --backend "
             "securemodernbert`, which is the only backend that stores them "
             "-- GLiNER/the gazetteer's types were measured ~20%% wrong in "
             "the 2026-09-11 decision this reopens for SecureModernBERT "
             "only; see entity_tagger.py's TYPE_MARKERS comment). Mutually "
             "exclusive with --replace-rare (unmeasured combination). "
             "Default: on with --ner-backend securemodernbert (the adopted "
             "standard, per project direction -- effort 17's own measured "
             "result on the CURRENT corpus was null, not negative, and "
             "typed is the configuration to re-test once the corpus "
             "expansion lands), off with 'gliner' (no typed artifact "
             "exists for it). Pass --no-typed-markers to reproduce effort "
             "16's generic-marker numbers on securemodernbert.",
    )
    parser.add_argument(
        "--replace-rare", action="store_true",
        help="Replace-mode entity normalisation (REPORT.md §8 item 7): rewrite "
             "each tagged span to a bare <ENTITY> marker instead of appending "
             "one, but ONLY where the span's measured corpus document "
             "frequency is below --df-cutoff. High-frequency tokens (`SQL`, "
             "`HTTP`, `Injection Attempt`) are left alone -- they carry the "
             "technique signal. Requires --entity-tagging and the DF artifact "
             "(`python -m attack_mapper.entity_ner.df_table`).",
    )
    parser.add_argument(
        "--df-cutoff", type=float, default=entity_tagger.DEFAULT_DF_CUTOFF,
        help="Document-frequency threshold for --replace-rare, as a fraction "
             "(0.01 = 1%% of corpus rows). A span is replaced only when its DF "
             "is strictly below this, so 0.0 replaces nothing and is a valid "
             "no-op control arm. Default: %(default)s.",
    )
    parser.add_argument(
        "--replacement-style", default=entity_tagger.DEFAULT_REPLACEMENT_STYLE,
        choices=list(entity_tagger.REPLACEMENT_STYLES),
        help="How a replaced span is substituted (with --replace-rare). "
             "'marker' inserts <ENTITY>, but note the classifier's word "
             "vectorizer strips the brackets, so it becomes the bare word "
             "'entity'; 'drop' removes the span entirely, on the hypothesis "
             "that in replace mode the removal IS the mechanism and the marker "
             "only dilutes; 'sentinel' inserts a collision-free token, "
             "separating 'does a placeholder help' from 'does it collide'. "
             "Default: %(default)s.",
    )
    parser.add_argument(
        "--reserved-placeholders", action="store_true",
        help="Substitute collision-free tokens (qqcveqq, qqipqq, qqhexqq, "
             "qqverqq) for <CVE>/<IP>/<HEX>/<VERSION>. The angle-bracket forms "
             "are NOT reserved tokens: the classifier's word vectorizer strips "
             "non-word characters, so <cve> is read as the ordinary word 'cve'. "
             "Independent of --entity-tagging; this changes BASELINE text, so "
             "it is off by default and every number on the branch assumes off.",
    )
    args = parser.parse_args()

    if args.replace_rare and not args.entity_tagging:
        parser.error("--replace-rare requires --entity-tagging "
                     "(it changes how spans are applied, not whether they are found)")
    if args.typed_markers is not None and not args.entity_tagging:
        parser.error("--typed-markers/--no-typed-markers requires --entity-tagging")

    # `--typed-markers` left unset (None) resolves per backend: on for
    # securemodernbert (the adopted standard -- effort 17), off for gliner
    # (no typed artifact exists for it). An explicit --typed-markers or
    # --no-typed-markers always wins over this default in either direction.
    if args.entity_tagging and args.typed_markers is None:
        args.typed_markers = (args.ner_backend == "securemodernbert")
    elif not args.entity_tagging:
        args.typed_markers = False



    check_required_data()

    # Set before the pipeline is constructed, for the same reason entity
    # tagging is: the resolvers canonicalize their whole corpus in __init__,
    # and the kNN cache key is derived from the normaliser fingerprint then.
    entity_tagger.RESERVED_PLACEHOLDERS = args.reserved_placeholders
    if args.reserved_placeholders:
        print("placeholders: RESERVED (qqcveqq/qqipqq/qqhexqq/qqverqq)")

    # Enable BEFORE the pipeline is constructed: the resolvers canonicalize
    # their whole corpus in __init__, and the kNN embedding cache key is
    # derived from the tagger's fingerprint at that moment.
    if args.entity_tagging:
        tagger = entity_tagger.enable(args.entity_tagging,
                                      replace_rare=args.replace_rare,
                                      df_cutoff=args.df_cutoff,
                                      replacement_style=args.replacement_style,
                                      ner_backend=args.ner_backend,
                                      typed_markers=args.typed_markers)
        if args.entity_tagging != "gazetteer_only":
            # Refuse a partial (--limit) spans artifact: it would silently
            # score like the off-baseline. See EntityTagger.assert_complete.
            from attack_mapper.entity_ner.build_spans import collect_texts
            tagger.assert_complete(len(collect_texts()))
        mode = (f"REPLACE rare spans (DF < {args.df_cutoff:.2%}, "
                f"style={args.replacement_style})"
                if args.replace_rare else "augment (append marker)")
        if args.typed_markers:
            mode += ", TYPED (per-type sentinel)"
        print(f"entity tagging: ON, merge rule '{args.entity_tagging}', "
              f"{mode}, {len(tagger.ner_spans)} texts in spans artifact")
    else:
        entity_tagger.disable()

    suffix = f"_entity_{args.entity_tagging}" if args.entity_tagging else ""
    if args.entity_tagging:
        # ALWAYS stamped, regardless of which backend is currently the
        # default. This used to be conditional ("only stamp a non-default
        # backend") to keep effort 13-15's gliner filenames unsuffixed --
        # but DEFAULT_NER_BACKEND flipped to securemodernbert at effort 17's
        # adoption, and that conditional silently collided a securemodernbert
        # run's filename with effort 13's *committed* gliner_only report
        # (both rendered as `validation_report_entity_gliner_only.md`),
        # overwriting it on disk the first time this ran post-flip. An
        # unconditional stamp can never collide across a future default
        # change again; the cost is that gliner runs are now (correctly)
        # suffixed too, so a handful of effort 13-16 filenames on disk
        # predate this and are not reproduced by today's default args.
        suffix += f"_{args.ner_backend}"
    if args.typed_markers:
        suffix += "_typed"
    if args.reserved_placeholders:
        suffix += "_reservedph"
    if args.replace_rare:
        # Each cutoff is a separate arm; without this the sweep overwrites one
        # report and only the last cutoff survives.
        suffix += f"_replace{args.df_cutoff:g}_{args.replacement_style}"
    out_path = os.path.join(
        HERE, f"validation_report_llm{suffix}.md" if args.llm
        else f"validation_report{suffix}.md")

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
    rejected_excluded = 0
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

        # `reviewer_verdict` semantics, ruled by the project owner 2026-09-11:
        #   "1" -- reviewer checked the mapping against the source of truth and
        #          agrees; score the row.
        #   "0" -- reviewer checked and the mapping is false; EXCLUDE the row
        #          from evaluation entirely.
        #   ""  -- not yet reviewed; scored, and reported as unconfirmed.
        # Before this, any non-empty verdict counted as "confirmed" and the 43
        # rejections were scored against the very label the reviewer rejected --
        # 36 of them scoreable, 22 counted as HITs, inflating micro by 2.2
        # points (38.8% -> 36.6%). See ../STATUS.md "What's not done".
        if (row.get("reviewer_verdict") or "").strip() == "0":
            rejected_excluded += 1
            ids = None

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
            is_confirmed = (row.get("reviewer_verdict") or "").strip() == "1"
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
                      if (r.get("reviewer_verdict") or "").strip() == "1")

    lines = [
        "# attack_mapper vs. hand-audited sample\n",
        f"- LLM reasoning layer (Layer D): {'Ollama ' + args.llm_model if llm_client else 'off (NullLLMClient)'}",
        (f"- entity-aware normalisation: **on**, merge rule "
         f"`{args.entity_tagging}`, NER backend `{args.ner_backend}` "
         f"({entity_tagger.active().stats()})"
         if args.entity_tagging else
         "- entity-aware normalisation: off (`normalize.canonicalize` unmodified)"),
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
        (f"- excluded by reviewer verdict `0` (mapping checked and rejected): "
         f"**{rejected_excluded}** rows -- these are not scored, per the 2026-09-11 ruling; "
         "scoring them against the rejected label previously inflated micro by 2.2 points"),
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
    print(f"excluded by reviewer verdict 0: {rejected_excluded}")
    print(f"human review required: {review_required_count}/{len(rows)}")
    print(f"source breakdown: {source_counts}")
    if pipeline.knn:
        print(f"kNN retrieval pool by corpus: {pipeline.knn.neighbour_source_counts}")
    if knn_corpus_acc:
        print("knn_corpus accuracy by winning corpus: " + ", ".join(
            f"{k} {h}/{n} = {h / n:.1%}" for k, (h, n) in sorted(knn_corpus_acc.items())))


if __name__ == "__main__":
    main()
