"""
Build a Sigma-derived (rule text -> ATT&CK technique) labeled corpus,
mirroring `../archive/tiered_approach/et_labeled_corpus.csv`'s format so the
two are directly comparable (a copy of that file also lives at
`../data/et_labeled_corpus.csv` for `classifier_resolver.py` to train on).

Purpose (see `findings.md`): `../archive/tiered_approach/
embedding_swap_findings.md` found Tier 2's weak accuracy isn't a feature-
representation problem but a training-corpus class-imbalance problem (the ET
corpus's top 5 techniques are 81.3% of rows; T1203 has exactly 1 example) --
and recommended folding in Sigma's ATT&CK-tagged rules specifically because
they cover different technique territory (host/EDR telemetry, client-side
techniques) that ET's network-rule corpus barely touches. This also doubles
as the first real-data stress test of `../extractors/sigma.py`, which until
then was only exercised against one hand-written fixture.

Usage: python build_corpus.py
Requires a local checkout of SigmaHQ/sigma's `rules/` directory at
./sigmahq/rules (see ../../STATUS.md or this file's header for how it was
fetched: sparse/shallow git clone, `rules/` only, ~3100 files, ~18MB).
Writes ../data/sigma_labeled_corpus.csv, ../data/sigma_parse_failures.csv,
and prints stats.
"""
import csv
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "sigmahq", "rules")
MITRE_MAPPING_DIR = os.path.normpath(os.path.join(HERE, "..", ".."))
OUT_CORPUS = os.path.join(HERE, "..", "data", "sigma_labeled_corpus.csv")
OUT_FAILURES = os.path.join(HERE, "..", "data", "sigma_parse_failures.csv")

sys.path.insert(0, MITRE_MAPPING_DIR)
from attack_mapper.extractors.sigma import SigmaExtractor  # noqa: E402
from attack_mapper.mitre_client import MitreAttackClient  # noqa: E402


def iter_rule_files(rules_dir):
    for root, _dirs, files in os.walk(rules_dir):
        for fn in files:
            if fn.endswith((".yml", ".yaml")):
                yield os.path.join(root, fn)


def main():
    if not os.path.isdir(RULES_DIR):
        raise SystemExit(f"{RULES_DIR} not found -- see this file's docstring for how to fetch it")

    extractor = SigmaExtractor()
    mitre = MitreAttackClient()

    total = 0
    parsed = 0
    failures = []
    no_technique_tag = 0
    corpus_rows = []

    for path in iter_rule_files(RULES_DIR):
        total += 1
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()

        try:
            if not extractor.can_extract(raw):
                failures.append((path, "can_extract=False", ""))
                continue
            rule = extractor.extract(raw, source_path=path)
        except Exception as exc:  # noqa: BLE001 -- want every real-world failure, not just expected ones
            failures.append((path, type(exc).__name__, str(exc)))
            continue

        parsed += 1
        if not rule.declared_technique_ids:
            no_technique_tag += 1
            continue

        tactics = set()
        for tid in rule.declared_technique_ids:
            tactics.update(mitre.get_tactics(tid))

        corpus_rows.append((
            rule.title or os.path.basename(path),
            ";".join(sorted(set(rule.declared_technique_ids))),
            ";".join(sorted(tactics)),
        ))

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
    print(f"parse failures: {len(failures)} ({len(failures) / total:.1%}) -> {OUT_FAILURES}")
    print(f"parsed but no attack.tXXXX tag: {no_technique_tag}")
    print(f"labeled corpus rows: {len(corpus_rows)} -> {OUT_CORPUS}")

    error_types = {}
    for _path, err, _msg in failures:
        error_types[err] = error_types.get(err, 0) + 1
    print("failure breakdown:", error_types)


if __name__ == "__main__":
    main()
