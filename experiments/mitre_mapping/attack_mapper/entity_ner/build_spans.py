"""
Precompute GLiNER entity spans for every text `canonicalize()` will ever see.

Plan §5 Step 2. A GLiNER pass runs at ~9.9 rows/s batched, so the ~32k corpus
rows cost ~54 minutes. `canonicalize()` is called once per corpus row on every
resolver construction, so doing this inline would add an hour to each
`validate.py` run. This script pays it once and writes an artifact that
`entity_tagger.py` reads.

**Raw spans are stored, not marked-up text.** The merge rule (union /
intersection / gliner_primary / ...) is applied at read time by
`entity_tagger.merge_spans`, so one 54-minute pass serves every variant of the
sweep. Storing final text instead would force a rebuild per rule.

Texts are keyed by `normalize.entity_key()` -- the vendor-prefix-stripped
title -- which is exactly the string `canonicalize()` hands the tagger. If the
two ever diverge, every lookup misses and the run silently degrades to
gazetteer-only.

Usage:
    python -m attack_mapper.entity_ner.build_spans            # full build (gliner)
    python -m attack_mapper.entity_ner.build_spans --backend securemodernbert
    python -m attack_mapper.entity_ner.build_spans --limit 200  # smoke test
    python -m attack_mapper.entity_ner.build_spans --resume     # keep existing
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
import time

from .. import entity_tagger
from ..corpora import CORPUS_PATHS
from ..normalize import entity_key

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, ".."))
DATA = os.path.join(PKG, "data")

# csv's default 128k field cap is smaller than some Sigma/Elastic rule bodies.
csv.field_size_limit(10 * 1024 * 1024)


def parse_proposed(cell):
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", cell)) or None


def collect_texts():
    """Every string that reaches `canonicalize()`: corpus rows (kNN retrieval
    pool + classifier training set) and eval signatures (queries).

    Eval rows include the non-scoreable ones deliberately -- they still run
    through the pipeline, and a cache miss there would trigger a live model
    load mid-run.
    """
    texts = set()
    corpus_n = 0
    for path in CORPUS_PATHS:
        if not os.path.exists(path):
            print(f"  (skipping absent {os.path.basename(path)})")
            continue
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if [t for t in row["technique_ids"].split(";") if t]:
                    texts.add(entity_key(row["msg"]))
                    corpus_n += 1
    print(f"  corpus rows: {corpus_n}")

    eval_rows = []
    for fn in sorted(glob.glob(os.path.join(DATA, "hand_audit_sample*.csv"))):
        eval_rows += list(csv.DictReader(open(fn, encoding="utf-8")))
    p = os.path.join(DATA, "labeled_set_v2.csv")
    if os.path.exists(p):
        eval_rows += list(csv.DictReader(open(p, encoding="utf-8")))
    for r in eval_rows:
        texts.add(entity_key(r["signature"]))
    print(f"  eval rows:   {len(eval_rows)}")

    return sorted(texts)


def _tag_gliner(todo, batch_size):
    print(f"loading {entity_tagger.NER_MODEL} ...")
    from gliner import GLiNER
    model = GLiNER.from_pretrained(entity_tagger.NER_MODEL)
    labels = list(entity_tagger.NER_LABELS)
    print("loaded.\n")

    spans = {}
    t0 = time.time()
    done = 0
    for i in range(0, len(todo), batch_size):
        chunk = todo[i:i + batch_size]
        results = model.batch_predict_entities(
            chunk, labels, threshold=entity_tagger.NER_THRESHOLD)
        for text, ents in zip(chunk, results):
            spans[text] = [[e["start"], e["end"], round(float(e["score"]), 4)]
                           for e in ents]
        done += len(chunk)
        if done % (batch_size * 25) == 0 or done == len(todo):
            el = time.time() - t0
            rate = done / el if el else 0
            eta = (len(todo) - done) / rate if rate else 0
            print(f"  {done}/{len(todo)}  {rate:.1f} rows/s  eta {eta / 60:.1f} min")
    return spans, t0


def _tag_securemodernbert(todo, batch_size):
    """No batch_predict_entities equivalent -- transformers' pipeline batches
    internally when given a list and `batch_size`, one call per chunk here
    only so progress can be printed at the same cadence as the GLiNER path."""
    print(f"loading {entity_tagger.SMB_MODEL} ...")
    from transformers import pipeline
    # `pipeline()` does NOT auto-select a GPU here -- measured directly:
    # omitting `device=` ran the 200-row benchmark at ~7-12 rows/s even with
    # CUDA installed and `torch.cuda.is_available()` True; passing `device=0`
    # measured ~98 rows/s on a GTX 1660 Ti (~5.5 min projected for the full
    # 32k-row corpus vs. 45-75 min on CPU). Falls back to CPU (-1) when no
    # GPU is present so this still runs on a CPU-only checkout.
    import torch
    device = 0 if torch.cuda.is_available() else -1
    print(f"  device: {'cuda:0 (' + torch.cuda.get_device_name(0) + ')' if device == 0 else 'cpu'}")
    pipe = pipeline("token-classification", model=entity_tagger.SMB_MODEL,
                    aggregation_strategy=entity_tagger.SMB_AGGREGATION,
                    device=device)
    print("loaded.\n")

    spans = {}
    t0 = time.time()
    done = 0
    for i in range(0, len(todo), batch_size):
        chunk = todo[i:i + batch_size]
        results = pipe(chunk, batch_size=batch_size)
        for text, ents in zip(chunk, results):
            # 4th element is the entity_group (`ORG`, `PRODUCT`, ...) --
            # effort 17's typed markers. GLiNER's spans (above) stay 3-wide;
            # entity_tagger._spans_for() reads len(s) > 3 to tell them apart.
            spans[text] = [[int(e["start"]), int(e["end"]),
                           round(float(e["score"]), 4), e["entity_group"]]
                          for e in ents]
        done += len(chunk)
        if done % (batch_size * 25) == 0 or done == len(todo):
            el = time.time() - t0
            rate = done / el if el else 0
            eta = (len(todo) - done) / rate if rate else 0
            print(f"  {done}/{len(todo)}  {rate:.1f} rows/s  eta {eta / 60:.1f} min")
    return spans, t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=entity_tagger.DEFAULT_NER_BACKEND,
                    choices=list(entity_tagger.NER_BACKENDS),
                    help="which NER model to tag with -- each backend writes "
                         "its own spans artifact (see entity_tagger.NER_BACKENDS)")
    ap.add_argument("--limit", type=int, default=0,
                    help="only tag the first N texts (smoke test)")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--resume", action="store_true",
                    help="keep spans already in the artifact, tag only new texts")
    ap.add_argument("--out", default=None,
                    help="defaults to the backend's own spans_path")
    args = ap.parse_args()

    backend_cfg = entity_tagger.NER_BACKENDS[args.backend]
    out_path = args.out or backend_cfg["spans_path"]

    print("collecting texts ...")
    texts = collect_texts()
    print(f"  distinct after dedupe: {len(texts)}")

    has_types = args.backend == "securemodernbert"

    existing = {}
    if args.resume and os.path.exists(out_path):
        with gzip.open(out_path, "rt", encoding="utf-8") as fh:
            blob = json.load(fh)
        same_model = blob.get("meta", {}).get("model") == backend_cfg["model"]
        # Gate resume on has_types too, not just model: a same-model artifact
        # built before effort 17 (3-wide spans, no label) resuming today
        # would silently mix 3-wide and 4-wide entries in one file. That is
        # exactly the "partial build scores like the baseline" failure
        # `assert_complete`'s docstring warns about, just from a schema
        # change instead of a --limit cutoff.
        same_types = blob.get("meta", {}).get("has_types") == has_types
        if same_model and same_types:
            existing = blob["spans"]
            print(f"  resuming: {len(existing)} already cached")
        elif same_model:
            print(f"  NOT resuming: existing artifact has_types="
                  f"{blob.get('meta', {}).get('has_types')!r}, this build "
                  f"wants {has_types!r} -- rebuilding from scratch")

    todo = [t for t in texts if t not in existing]
    if args.limit:
        todo = todo[:args.limit]
    print(f"  to tag: {len(todo)}  (backend: {args.backend})\n")

    if not todo:
        print("nothing to do.")
        return 0

    if args.backend == "securemodernbert":
        new_spans, t0 = _tag_securemodernbert(todo, args.batch)
    else:
        new_spans, t0 = _tag_gliner(todo, args.batch)
    spans = dict(existing)
    spans.update(new_spans)

    tagged = sum(1 for v in spans.values() if v)
    total_ents = sum(len(v) for v in spans.values())

    blob = {
        "meta": {
            "backend": args.backend,
            "model": backend_cfg["model"],
            "threshold": backend_cfg["threshold"],
            "labels": list(backend_cfg["labels"]) if backend_cfg["labels"] else None,
            "has_types": has_types,
            "built": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "n_texts": len(spans),
            "note": "keyed by normalize.entity_key(); raw spans, merge applied at read time",
        },
        "spans": spans,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8") as fh:
        json.dump(blob, fh)

    size_mb = os.path.getsize(out_path) / 1e6
    print(f"\nwrote {out_path}  ({size_mb:.1f} MB)")
    print(f"  texts: {len(spans)}   with >=1 entity: {tagged} ({tagged / len(spans):.1%})")
    print(f"  total entities: {total_ents}")
    print(f"  elapsed: {(time.time() - t0) / 60:.1f} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
