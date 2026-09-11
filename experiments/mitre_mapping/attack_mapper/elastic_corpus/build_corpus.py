"""
Build an Elastic-derived (rule text -> ATT&CK technique) labeled corpus,
mirroring `../data/sigma_labeled_corpus.csv`'s format so all corpora are
directly comparable and `classifier_resolver.py` / `knn_resolver.py` can
concatenate them without special-casing.

Purpose (see `../../STATUS.md` effort 11 and `findings.md` here): the two
dominant candidate sources, `supervised_classifier` (45.2%) and `knn_corpus`
(27.9%), answer 350 of 397 scoreable rows and both draw on the same
ET+Sigma corpus. That corpus is enormous but narrow -- ET contributes 26,644
rows covering only 45 distinct techniques, which is what drives the T1190
hub collapse (predicted on 33.5% of rows against a 28.5% true base rate,
micro 38.8% vs macro 21.1%). Elastic's detection-rules carry hand-written
ATT&CK mappings across host/cloud/network telemetry, so they add technique
*diversity* rather than more rows in the same few classes.

Granularity note -- this differs deliberately from the Sigma corpus:
Sigma authors tag one granularity per rule (`attack.t1021.004`), so
`extractors/sigma.py` emits exactly what was tagged. Elastic instead nests
`[[rule.threat.technique.subtechnique]]` blocks *inside* the parent
`[[rule.threat.technique]]`, asserting both. Both are emitted here, because
a sub-technique detection genuinely is a detection of its parent and the
500-row evaluation set is predominantly parent-level (T1190, T1046, T1018).
Emitting sub-techniques alone would produce labels that can never match a
parent-level ground truth.

Usage: python build_corpus.py
Requires a local checkout under ./detection-rules/ (gitignored, re-clonable):
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/elastic/detection-rules.git
    cd detection-rules && git sparse-checkout set rules

Skips `rules/_deprecated/` and any rule with `metadata.maturity =
"deprecated"` -- retired detections whose ATT&CK mappings are no longer
maintained.

Writes ../data/elastic_labeled_corpus.csv, ../data/elastic_parse_failures.csv,
and prints the diversity stats (distinct techniques, top-5 share) that
../../STATUS.md compares corpora on.
"""
import csv
import os
import tomllib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "detection-rules", "rules")
OUT_CORPUS = os.path.normpath(os.path.join(HERE, "..", "data", "elastic_labeled_corpus.csv"))
OUT_FAILURES = os.path.normpath(os.path.join(HERE, "..", "data", "elastic_parse_failures.csv"))


def iter_rule_files(rules_dir):
    for root, _dirs, files in os.walk(rules_dir):
        if "_deprecated" in root.replace("\\", "/").split("/"):
            continue
        for fn in files:
            if fn.endswith(".toml"):
                yield os.path.join(root, fn)


def extract_labels(doc):
    """Returns (technique_ids, tactic_ids) from a parsed Elastic rule.

    `rule.threat` is a list of blocks, each with an optional list of
    `technique` entries (themselves carrying an optional `subtechnique`
    list) and one `tactic` table. Every level is optional in practice --
    some rules declare a tactic with no technique at all.
    """
    techniques, tactics = set(), set()
    for threat in doc.get("rule", {}).get("threat", []) or []:
        tactic = threat.get("tactic") or {}
        if tactic.get("id"):
            tactics.add(tactic["id"])
        for technique in threat.get("technique", []) or []:
            if technique.get("id"):
                techniques.add(technique["id"])
            for sub in technique.get("subtechnique", []) or []:
                if sub.get("id"):
                    techniques.add(sub["id"])
    return techniques, tactics


def main():
    if not os.path.isdir(RULES_DIR):
        raise SystemExit(f"{RULES_DIR} not found -- see this file's docstring for how to fetch it")

    total = parsed = deprecated = no_technique = 0
    failures = []
    corpus_rows = []

    for path in iter_rule_files(RULES_DIR):
        total += 1
        try:
            with open(path, "rb") as fh:
                doc = tomllib.load(fh)
        except Exception as exc:  # noqa: BLE001 -- want every real-world failure
            failures.append((path, type(exc).__name__, str(exc)))
            continue

        parsed += 1
        if (doc.get("metadata") or {}).get("maturity") == "deprecated":
            deprecated += 1
            continue

        name = (doc.get("rule") or {}).get("name")
        if not name:
            failures.append((path, "NoRuleName", "rule.name missing"))
            continue

        techniques, tactics = extract_labels(doc)
        if not techniques:
            no_technique += 1
            continue

        corpus_rows.append((name, ";".join(sorted(techniques)), ";".join(sorted(tactics))))

    with open(OUT_CORPUS, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["msg", "technique_ids", "tactic_ids"])
        w.writerows(corpus_rows)

    with open(OUT_FAILURES, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "error_type", "message"])
        w.writerows(failures)

    print(f"total rule files: {total}")
    print(f"parsed: {parsed} ({parsed / total:.1%})")
    print(f"parse failures: {len(failures)} -> {OUT_FAILURES}")
    print(f"skipped (maturity=deprecated): {deprecated}")
    print(f"parsed but no ATT&CK technique: {no_technique}")
    print(f"labeled corpus rows: {len(corpus_rows)} -> {OUT_CORPUS}")

    freq = Counter(t for _msg, tids, _tac in corpus_rows for t in tids.split(";"))
    total_labels = sum(freq.values())
    print(f"distinct techniques: {len(freq)}")
    if total_labels:
        top5 = freq.most_common(5)
        share = sum(c for _t, c in top5) / total_labels
        print(f"top-5-techniques share: {share:.1%} ({', '.join(f'{t} x{c}' for t, c in top5)})")


if __name__ == "__main__":
    main()
