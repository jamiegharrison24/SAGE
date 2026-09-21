"""
How often does each merge rule actually fire, and is `<ENTITY>` a feature or a
constant?

This runs before any `validate.py` pass, because it can rule arms out cheaply.
Both downstream consumers are frequency-sensitive:

  * the classifier is char+word TF-IDF -- a token present in ~every document
    has near-zero IDF and contributes nothing, so a rule that tags 95% of rows
    has added a constant, not a feature;
  * the kNN layer embeds the whole string, so a near-constant token still
    shifts every other token's relative weight -- cost without signal.

So a rule firing on *almost everything* is as uninformative as one firing on
almost nothing, and the useful arms sit in between. Reports per rule:
row coverage, mean markers per tagged row, and the marker's document
frequency, over the corpus and the eval set separately.

Usage:
    python -m attack_mapper.entity_ner.marker_rate
    python -m attack_mapper.entity_ner.marker_rate --backend securemodernbert
    python -m attack_mapper.entity_ner.marker_rate --backend securemodernbert --per-type

--per-type (effort 17, typed markers): the near-constant/too-sparse verdict
above is for ONE merged marker across ALL entity types. Splitting `union`'s
89.4%-of-corpus coverage (comparison_findings.md's "Pipeline integration"
section) across ~22 types means no single type need be near-constant even
though the merged rule is -- which would make NER-only markers viable again
under typing where they were ruled out generic. Run this BEFORE spending a
`validate.py --typed-markers` pass: it is the same "rule out arms in
seconds" cheap check the un-typed screen above already is.
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
from collections import Counter

from .. import entity_tagger as et
from ..corpora import CORPUS_PATHS
from ..normalize import entity_key

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(HERE, "..", "data"))

csv.field_size_limit(10 * 1024 * 1024)


def parse_proposed(cell):
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", cell)) or None


def corpus_texts():
    out = []
    for path in CORPUS_PATHS:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if [t for t in row["technique_ids"].split(";") if t]:
                    out.append(entity_key(row["msg"]))
    return out


def eval_texts(scoreable_only=True):
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA, "hand_audit_sample*.csv"))):
        rows += list(csv.DictReader(open(fn, encoding="utf-8")))
    p = os.path.join(DATA, "labeled_set_v2.csv")
    if os.path.exists(p):
        rows += list(csv.DictReader(open(p, encoding="utf-8")))
    if scoreable_only:
        rows = [r for r in rows if parse_proposed(r["proposed_technique"]) is not None]
    return [entity_key(r["signature"]) for r in rows]


def per_type_report(ner, sets):
    """Coverage broken down by entity type, over NER spans only (`gl` in
    entity_tagger's merge terms -- the gazetteer is never typed, see
    TYPE_MARKERS). One row per type using the same near-constant/too-sparse/
    informative verdict as the merge-rule table, so the two are read the
    same way.
    """
    for setname, texts in sets.items():
        print("=" * 72)
        print(f"{setname}  --  per-type coverage (NER spans only)")
        print("=" * 72)
        print(f"{'type':>16} {'rows tagged':>13} {'markers/tagged':>16} {'verdict':>22}")

        by_type = {}  # etype -> [tagged, markers]
        for t in texts:
            cached = ner.get(t, [])
            seen_types = set()
            for s in cached:
                etype = s[3] if len(s) > 3 else None
                if etype is None:
                    continue  # untyped artifact -- caller should have refused already
                counts = by_type.setdefault(etype, [0, 0])
                counts[1] += 1
                seen_types.add(etype)
            for etype in seen_types:
                by_type[etype][0] += 1

        for etype in sorted(by_type, key=lambda k: -by_type[k][0]):
            tagged, markers = by_type[etype]
            cov = tagged / len(texts) if texts else 0
            mpt = markers / tagged if tagged else 0
            if cov >= 0.85:
                verdict = "near-constant"
            elif cov <= 0.10:
                verdict = "too sparse"
            else:
                verdict = "informative range"
            print(f"{etype:>16} {tagged:>6} ({cov:>5.1%}) {mpt:>16.2f} {verdict:>22}")
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=et.DEFAULT_NER_BACKEND,
                    choices=list(et.NER_BACKENDS))
    ap.add_argument("--per-type", action="store_true",
                    help="Break down coverage by entity type instead of by "
                         "merge rule. Needs an artifact with per-span types "
                         "(securemodernbert) -- see module docstring.")
    args = ap.parse_args()
    spans_path = et.NER_BACKENDS[args.backend]["spans_path"]

    if not os.path.exists(spans_path):
        raise SystemExit(f"{spans_path} not found -- run "
                          f"`build_spans.py --backend {args.backend}` first")
    with gzip.open(spans_path, "rt", encoding="utf-8") as fh:
        blob = json.load(fh)
    ner = blob["spans"]
    meta = blob["meta"]
    print(f"artifact: {meta['n_texts']} texts, model {meta['model']} @ {meta['threshold']}")
    print(f"          built {meta['built']}\n")

    sets = {"corpus": corpus_texts(), "eval (scoreable)": eval_texts()}

    if args.per_type:
        if not meta.get("has_types"):
            raise SystemExit(f"{spans_path} has no per-span types "
                             f"(has_types={meta.get('has_types')!r}) -- "
                             f"rebuild with `build_spans.py --backend "
                             f"{args.backend}`")
        per_type_report(ner, sets)
        return 0

    single, multi = et.load_gazetteer()

    for setname, texts in sets.items():
        print("=" * 72)
        print(f"{setname}  --  {len(texts)} rows ({len(set(texts))} distinct)")
        print("=" * 72)
        print(f"{'rule':>16} {'rows tagged':>13} {'markers/tagged':>16} {'verdict':>22}")

        for rule in et.MERGE_RULES:
            tagged = 0
            markers = 0
            for t in texts:
                spans = []
                if rule != "gliner_only":
                    spans += et.gazetteer_spans(t, single, multi)
                if rule != "gazetteer_only":
                    spans += [(s[0], s[1], "gliner") for s in ner.get(t, [])]
                merged = et.merge_spans(spans, rule)
                if merged:
                    tagged += 1
                    markers += len(merged)
            cov = tagged / len(texts) if texts else 0
            mpt = markers / tagged if tagged else 0
            if cov >= 0.85:
                verdict = "near-constant"
            elif cov <= 0.10:
                verdict = "too sparse"
            else:
                verdict = "informative range"
            print(f"{rule:>16} {tagged:>6} ({cov:>5.1%}) {mpt:>16.2f} {verdict:>22}")
        print()

    # Which strings get tagged most -- the noise check. A rule whose top tags
    # are generic English ("directory", "engine") is re-measuring Step 1's 53%.
    print("=" * 72)
    print("most-tagged strings on the eval set, per rule (noise check)")
    print("=" * 72)
    for rule in ("gliner_only", "intersection", "union"):
        freq = Counter()
        for t in sets["eval (scoreable)"]:
            spans = []
            if rule != "gliner_only":
                spans += et.gazetteer_spans(t, single, multi)
            if rule != "gazetteer_only":
                spans += [(s[0], s[1], "gliner") for s in ner.get(t, [])]
            for a, b in et.merge_spans(spans, rule):
                freq[t[a:b].lower()] += 1
        top = ", ".join(f"{w}x{c}" for w, c in freq.most_common(12))
        print(f"\n  [{rule}] {len(freq)} distinct\n    {top}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
