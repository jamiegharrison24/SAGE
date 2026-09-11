"""
Build a Splunk-derived (rule text -> ATT&CK technique) labeled corpus,
mirroring `../data/sigma_labeled_corpus.csv`'s format so all corpora
concatenate without special-casing (see `../corpora.py`).

Purpose (see `findings.md` here, and `../elastic_corpus/findings.md`): the
`supervised_classifier` and `knn_corpus` retrieval both draw on the same
labeled corpus, and that corpus is ET-dominated -- 26,644 of its rows cover
only 45 distinct techniques, which drives the T1190 hub collapse. Splunk's
security_content carries hand-written ATT&CK IDs across endpoint/cloud/web/
network analytics, adding technique breadth rather than more rows in the
same few classes.

Granularity note: each corpus is kept faithful to what its rules actually
assert. Splunk tags a single ID per entry at the author's chosen granularity
(`T1552.002`), exactly like Sigma, so that is what is emitted here. Elastic
is the exception -- it nests `subtechnique` blocks *inside* the parent
`technique` block, asserting both, so `../elastic_corpus/build_corpus.py`
emits both. Deriving parents from sub-techniques everywhere is a separate
experiment (it would change the class-prior and IDF denominators for every
corpus at once) and is deliberately not mixed into this one.

Schema note: `mitre_attack_id` is a **top-level** key in the current
security_content schema. Older revisions nested it under `tags:`, so both
are read -- verified against the live checkout rather than assumed.

Usage: python build_corpus.py
Requires a local checkout under ./security_content/ (gitignored, re-clonable):
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/splunk/security_content.git
    cd security_content && git sparse-checkout set detections

Skips `detections/deprecated/` and any detection with `status: deprecated`.
`status: experimental` rules are kept -- they carry real author-assigned
ATT&CK IDs and the corpus is training data, not a production ruleset.

Writes ../data/splunk_labeled_corpus.csv, ../data/splunk_parse_failures.csv,
and prints the diversity stats ../../STATUS.md compares corpora on.
"""
import csv
import os
from collections import Counter

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DETECTIONS_DIR = os.path.join(HERE, "security_content", "detections")
OUT_CORPUS = os.path.normpath(os.path.join(HERE, "..", "data", "splunk_labeled_corpus.csv"))
OUT_FAILURES = os.path.normpath(os.path.join(HERE, "..", "data", "splunk_parse_failures.csv"))

_TECHNIQUE_PREFIX = "T"


def iter_rule_files(detections_dir):
    for root, _dirs, files in os.walk(detections_dir):
        if "deprecated" in root.replace("\\", "/").split("/"):
            continue
        for fn in files:
            if fn.endswith((".yml", ".yaml")):
                yield os.path.join(root, fn)


def extract_technique_ids(doc):
    """Top-level `mitre_attack_id` in the current schema; `tags.mitre_attack_id`
    in older revisions. Returns a set of `T####[.###]` strings."""
    raw = doc.get("mitre_attack_id")
    if raw is None:
        raw = (doc.get("tags") or {}).get("mitre_attack_id")
    if not raw:
        return set()
    if isinstance(raw, str):
        raw = [raw]
    return {
        str(t).strip().upper() for t in raw
        if str(t).strip().upper().startswith(_TECHNIQUE_PREFIX)
    }


def main():
    if not os.path.isdir(DETECTIONS_DIR):
        raise SystemExit(f"{DETECTIONS_DIR} not found -- see this file's docstring for how to fetch it")

    total = parsed = deprecated = no_technique = 0
    failures = []
    corpus_rows = []

    for path in iter_rule_files(DETECTIONS_DIR):
        total += 1
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:  # noqa: BLE001 -- want every real-world failure
            failures.append((path, type(exc).__name__, str(exc)))
            continue

        if not isinstance(doc, dict):
            failures.append((path, "NotAMapping", f"top level parsed as {type(doc).__name__}"))
            continue

        parsed += 1
        if doc.get("status") == "deprecated":
            deprecated += 1
            continue

        name = doc.get("name")
        if not name:
            failures.append((path, "NoRuleName", "name missing"))
            continue

        techniques = extract_technique_ids(doc)
        if not techniques:
            no_technique += 1
            continue

        # No tactic IDs in this schema -- the column stays empty rather than
        # being back-derived, since nothing downstream reads it.
        corpus_rows.append((name, ";".join(sorted(techniques)), ""))

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
    print(f"skipped (status=deprecated): {deprecated}")
    print(f"parsed but no mitre_attack_id: {no_technique}")
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
