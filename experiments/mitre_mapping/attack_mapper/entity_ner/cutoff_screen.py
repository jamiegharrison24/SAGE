"""
Does the DF cutoff actually separate arms? Pre-screen before spending a
`validate.py` pass per cutoff.

Same role as `marker_rate.py`, one level down: `marker_rate` asks whether a
merge rule fires often enough to be a feature, this asks whether the *DF gate*
distinguishes the cutoffs in the sweep. `gliner_only` fires on ~42% of corpus
rows and GLiNER-at-0.85 spans are mostly rare by construction, so it is
entirely possible that 0.005 and 0.05 replace nearly the same spans -- in which
case the five-arm sweep is one arm plus noise, and running it would burn five
validate passes to rediscover that.

Reports, per cutoff: spans replaced vs kept, rows touched, and which
high-frequency strings survive. The last column is the safety check -- if
`SQL` or `Injection Attempt` ever appear in the replaced set, the gate is not
doing its job and no accuracy number from that arm is meaningful.

Usage:
    python -m attack_mapper.entity_ner.cutoff_screen
    python -m attack_mapper.entity_ner.cutoff_screen --cutoffs 0 0.01 0.1
"""
import argparse
from collections import Counter

from .. import entity_tagger as et
from .build_spans import collect_texts
from .df_table import DFTable

DEFAULT_CUTOFFS = (0.0, 0.005, 0.01, 0.02, 0.05)

# If any of these is ever replaced, the gate has destroyed the technique
# signal -- the exact failure the DF cut exists to prevent.
MUST_KEEP = ("sql", "injection attempt", "http", "dns")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoffs", type=float, nargs="*", default=list(DEFAULT_CUTOFFS))
    ap.add_argument("--merge-rule", default="gliner_only", choices=list(et.MERGE_RULES))
    args = ap.parse_args()

    tagger = et.EntityTagger(merge_rule=args.merge_rule)
    table = DFTable()
    # `collect_texts()` is exactly what build_spans.py tagged and what
    # validate.py checks against -- the same denominator, so the completeness
    # guard keeps its real 2% tolerance here instead of being loosened to
    # paper over a mismatched count.
    texts = collect_texts()
    tagger.assert_complete(len(texts))

    print(f"merge rule: {args.merge_rule}   texts: {len(texts)} "
          f"({len(set(texts))} distinct)")
    print(f"DF table: {table.meta['n_docs']} docs, "
          f"{table.meta['n_kept']} n-grams\n")

    # Collect spans once; the cutoffs only re-filter the same list.
    surfaces = []
    rows_with_spans = 0
    for t in texts:
        merged = et.merge_spans(tagger._spans_for(t), args.merge_rule)
        if merged:
            rows_with_spans += 1
        surfaces.append([t[s:e] for s, e in merged])

    total_spans = sum(len(s) for s in surfaces)
    print(f"rows with >=1 span: {rows_with_spans}/{len(texts)} "
          f"({rows_with_spans / len(texts):.1%})")
    print(f"total spans: {total_spans}\n")

    print(f"{'cutoff':>8} {'replaced':>10} {'kept':>8} {'% repl':>8} "
          f"{'rows touched':>14} {'emptied':>9} {'must-keep hit':>15}")
    prev = None
    for c in args.cutoffs:
        replaced = kept = touched = emptied = 0
        violations = Counter()
        for text, spans in zip(texts, surfaces):
            hit = False
            surviving = text
            for s in spans:
                if table.is_rare(s, c):
                    replaced += 1
                    hit = True
                    surviving = surviving.replace(s, "", 1)
                    if s.strip().lower() in MUST_KEEP:
                        violations[s.strip().lower()] += 1
                else:
                    kept += 1
            if hit:
                touched += 1
                # Under `drop` these texts would become empty documents --
                # an all-zero TF-IDF row that still yields a prediction.
                # `replace_spans` floors them, but a large count here means
                # the `drop` arm is quietly falling back on many rows.
                if not surviving.strip():
                    emptied += 1
        pct = replaced / total_spans if total_spans else 0.0
        flag = ", ".join(f"{k}x{v}" for k, v in violations.items()) or "-- none"
        print(f"{c:>8.4g} {replaced:>10} {kept:>8} {pct:>7.1%} "
              f"{touched:>14} {emptied:>9} {flag:>15}")
        if prev is not None and total_spans:
            delta = abs(replaced - prev) / total_spans
            if delta < 0.01:
                print(f"{'':>8} ^ within 1% of the previous cutoff -- these two "
                      f"arms are not distinguishable")
        prev = replaced

    print("\nIf the middle cutoffs are within ~1% of each other, collapse the "
          "sweep: they are one arm, and 'no cutoff separates' is the finding.")


if __name__ == "__main__":
    main()
