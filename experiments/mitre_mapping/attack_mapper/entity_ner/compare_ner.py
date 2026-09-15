"""
Span-level comparison of the three NER candidates on ONE fixed title sample.

`findings.md` left NuNER Zero and SecureBERT2.0-NER unrun, and the numbers
quoted for GLiNER (47% precision at threshold 0.5, 73% at 0.85) came from hand
verdicts that were never written back -- `trial_sample.csv` ships with an empty
`verdict` column. So GLiNER is re-run here alongside the others rather than
cited: a comparison against an unreproducible number is not a comparison.

Deliberately span-level only. The plan gates the 26-minute corpus pass and any
`validate.py` arm on a model winning here first, and `marker_rate.py` can
pre-screen merge rules in seconds after that. Nothing in this file touches
`normalize.py` or the spans artifact.

The three models are not peers:

  * `urchade/gliner_medium-v2.1` -- apache-2.0, the incumbent. Span-level
    zero-shot; the threshold is a real lever (see the sweep in findings.md).
  * `numind/NuNER_Zero` -- MIT, the plan's co-primary (§5, line 320). GLiNER
    architecture but a *token* classifier, so adjacent same-label tokens must
    be merged into spans; the model card's own `merge_entities` is reproduced
    below. Expected to beat GLiNER on multi-word spans, which is exactly the
    axis Step 1's gazetteer structurally cannot reach.
  * `cisco-ai/SecureBERT2.0-NER` -- apache-2.0, but a one-off sanity check,
    NOT a third arm (plan §5, line 321: "wrong schema, prose-only per its own
    card"). Its label schema is fixed, so the open question is narrow and
    recorded: does its `System` type actually cover software products?

Sample: the same 30 scoreable eval titles `trial.py` draws at seed 11, so this
is directly comparable to the effort-13 run rather than a fresh draw.

Usage:
    python -m attack_mapper.entity_ner.compare_ner
    python -m attack_mapper.entity_ner.compare_ner --models gliner,nuner
"""
import argparse
import csv
import os
import random
import sys

from ..normalize import entity_key
from .trial import LABELS, PROBE, load_scoreable_titles

HERE = os.path.dirname(os.path.abspath(__file__))

GLINER_MODEL = "urchade/gliner_medium-v2.1"
NUNER_MODEL = "numind/NuNER_Zero"
SECUREBERT_MODEL = "cisco-ai/SecureBERT2.0-NER"


def merge_entities(text, entities):
    """Stitch token-level predictions back into spans.

    Verbatim in behaviour from the NuNER Zero model card. A token classifier
    emits one prediction per token, so `Nmap Scripting Engine` arrives as three
    adjacent `hacking tool` predictions; without this the model is penalised
    for the very capability it is being tested on. Adjacent runs sharing a
    label are joined when separated by nothing or a single space.
    """
    if not entities:
        return []
    merged = []
    current = entities[0]
    for nxt in entities[1:]:
        gap = text[current["end"]:nxt["start"]]
        if nxt["label"] == current["label"] and gap in (" ", ""):
            current["text"] = text[current["start"]:nxt["end"]]
            current["end"] = nxt["end"]
        else:
            merged.append(current)
            current = nxt
    merged.append(current)
    return merged


def run_gliner(model_name, titles, threshold):
    from gliner import GLiNER
    model = GLiNER.from_pretrained(model_name)
    out = {}
    for t in titles:
        ents = model.predict_entities(t, LABELS, threshold=threshold)
        out[t] = sorted(ents, key=lambda e: e["start"])
    return out


def run_nuner(titles, threshold):
    """NuNER Zero. Labels must be lowercase per the model card, and the raw
    output is token-level -- see `merge_entities`."""
    from gliner import GLiNER
    model = GLiNER.from_pretrained(NUNER_MODEL)
    labels = [lbl.lower() for lbl in LABELS]
    out = {}
    for t in titles:
        ents = model.predict_entities(t, labels, threshold=threshold)
        ents = sorted(ents, key=lambda e: e["start"])
        out[t] = merge_entities(t, ents)
    return out


def run_securebert(titles, aggregation="first"):
    """Fixed-schema token classification -- no declared labels, no threshold
    lever. The aggregation strategy does the span stitching.

    Default `first`, not `simple`. Under `simple` the model returns subword
    fragments (`'PL'`, `'OIT'`, `'wd'`) because it assigns *different* labels
    to adjacent subwords of one word, which blocks grouping. `first` takes the
    first subword's label for the whole word, which is the fair word-level
    read -- judging a model on fragments its tokenizer produced would be
    measuring the config, not the model.
    """
    from transformers import pipeline
    pipe = pipeline("token-classification", model=SECUREBERT_MODEL,
                    aggregation_strategy=aggregation)
    out = {}
    for t in titles:
        ents = []
        for e in pipe(t):
            start, end = int(e["start"]), int(e["end"])
            ents.append({"start": start, "end": end, "text": t[start:end],
                         "label": e["entity_group"], "score": float(e["score"])})
        out[t] = sorted(ents, key=lambda e: e["start"])
    return out


def report(name, results, titles):
    fired = sum(1 for t in titles if results[t])
    total = sum(len(results[t]) for t in titles)
    print("\n" + "=" * 78)
    print(f"{name}  --  fired on {fired}/{len(titles)} titles "
          f"({fired / len(titles):.0%}), {total} entities")
    print("=" * 78)
    for t in titles:
        rendered = ", ".join(
            f"{e['text']!r}->{e['label']} ({e['score']:.2f})" for e in results[t]
        ) or "(none)"
        print(f"\n  {t[:76]}")
        print(f"     {rendered}")
    return fired, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="gliner,nuner,securebert")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="zero-shot models only; the sweep happens post-hoc "
                         "off the recorded scores, so collect at 0.5")
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--seed", type=int, default=11,
                    help="11 reproduces trial.py's effort-13 sample exactly")
    ap.add_argument("--aggregation", default="first",
                    choices=["first", "simple", "max", "average"],
                    help="SecureBERT only -- subword grouping strategy")
    ap.add_argument("--raw-titles", action="store_true",
                    help="tag the unstripped title (diagnostic only -- the "
                         "pipeline never sees this string)")
    ap.add_argument("--probe", action="store_true",
                    help="also run the hand-picked PROBE set (qualitative only)")
    args = ap.parse_args()

    random.seed(args.seed)
    raw = random.sample(load_scoreable_titles(), args.sample)

    # Tag `entity_key(title)`, not the raw title. `build_spans.py` and
    # `marker_rate.py` both key on `entity_key`, and `canonicalize()` strips
    # the vendor prefix *before* handing text to the tagger -- so `ET `,
    # `GPL `, `ETPRO`, `OS-` and `INDICATOR-` are not in the string any model
    # sees in production. Measuring on raw titles credits or penalises models
    # for spans that can never occur, which is the same train/inference
    # asymmetry `findings.md` names as a fake-result generator.
    titles = [entity_key(t) for t in raw]
    if not args.raw_titles:
        stripped = sum(1 for a, b in zip(raw, titles) if a != b)
        print(f"tagging entity_key(title): vendor prefix stripped from "
              f"{stripped}/{len(raw)} titles")
    else:
        titles = raw
        print("WARNING: --raw-titles measures text the pipeline never sees")

    wanted = [m.strip() for m in args.models.split(",") if m.strip()]

    runners = {
        "gliner": lambda ts: run_gliner(GLINER_MODEL, ts, args.threshold),
        "nuner": lambda ts: run_nuner(ts, args.threshold),
        "securebert": lambda ts: run_securebert(ts, args.aggregation),
    }

    rows = []
    summary = []
    for name in wanted:
        if name not in runners:
            raise SystemExit(f"unknown model {name!r}; pick from {list(runners)}")
        print(f"\nloading {name} ...", flush=True)
        probe = [entity_key(t) for t in PROBE] if not args.raw_titles else list(PROBE)
        run_on = titles + probe if args.probe else titles
        results = runners[name](run_on)
        fired, total = report(name, results, titles)
        summary.append((name, fired, total))
        for t in titles:
            for e in results[t]:
                rows.append((name, t, e["text"], e["label"],
                             f"{e['score']:.3f}", e["start"], e["end"], ""))
        if args.probe:
            print(f"\n[{name}] PROBE set (qualitative, NOT scored)")
            for t in probe:
                ents = results.get(t) or []
                print(f"  {t[:70]}\n     "
                      + (", ".join(f"{e['text']!r}->{e['label']}" for e in ents)
                         or "(none)"))

    # Named by the arms it contains, so a single-model re-run cannot silently
    # clobber a full three-way sweep that has already been hand-verdicted.
    out = os.path.join(HERE, f"compare_sample_{'-'.join(wanted)}.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "signature", "entity", "label", "score",
                    "start", "end", "verdict"])
        w.writerows(rows)

    print("\n\n" + "=" * 78)
    print(f"{'model':>12} {'titles fired':>14} {'entities':>10}")
    for name, fired, total in summary:
        print(f"{name:>12} {fired:>6}/{len(titles)} ({fired / len(titles):>4.0%}) "
              f"{total:>10}")
    print(f"\nwrote {len(rows)} entities for hand verdict -> {out}")
    print("Verdict column is empty on purpose -- fill it before quoting precision.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
