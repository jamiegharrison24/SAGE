"""
Measured corpus document frequency for entity spans -- the "rare" cut for
replace-mode tagging (REPORT.md §8 item 7).

Replace-mode rewrites a span to a bare `<ENTITY>` marker, which destroys the
surface token. That is the point for a rare string (`ASA 5500 Series` carries
no technique signal and blocks two rules from looking alike) and a disaster for
a frequent one (`SQL` at DF 12.1% and `Injection Attempt` at 12.0% ARE the
technique signal). So replacement has to be gated on frequency.

The report is explicit that the cut is made on **measured corpus document
frequency, not a hand-written protocol list** -- a hand list encodes the
author's guess about which tokens matter, which is the thing being tested.

What DF means here: the share of corpus documents whose token stream contains
the span's token sequence. Computed as n-gram DF (n up to `MAX_NGRAM`) rather
than per-candidate substring scans, which would be O(candidates x documents).

Keying matches `build_spans.py` and `verdicts.py`: `entity_key(msg)`, the
vendor-prefix-stripped title. The first NER comparison pass keyed on raw
titles instead and had to be redone (REPORT.md effort 13) -- do not "simplify"
this to `row["msg"]`.

Usage:
    python -m attack_mapper.entity_ner.df_table              # build + summary
    python -m attack_mapper.entity_ner.df_table --show SQL   # probe strings
"""
import argparse
import csv
import gzip
import json
import os
import re
from collections import Counter

from ..corpora import CORPUS_PATHS
from ..normalize import entity_key

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(HERE, "..", "data"))
DF_PATH = os.path.join(DATA, "entity_df.json.gz")

csv.field_size_limit(10 * 1024 * 1024)

# Longest span measured. GLiNER spans above 5 tokens are vanishingly rare and
# every one of them is rare by construction, so they fall through to the
# "unseen => rare" default rather than inflating the table.
MAX_NGRAM = 5

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")


def tokenize(text):
    """Lowercase token stream. Mirrors `entity_tagger._TOKEN_RE` so a span's
    tokens and a document's tokens are cut the same way."""
    return _TOKEN_RE.findall(text.lower())


def ngrams(tokens, max_n=MAX_NGRAM):
    """Every contiguous token sequence up to `max_n`, as space-joined keys."""
    out = set()
    for n in range(1, max_n + 1):
        for i in range(len(tokens) - n + 1):
            out.add(" ".join(tokens[i:i + n]))
    return out


def corpus_documents():
    """Corpus rows exactly as the resolvers see them.

    Filtered to rows carrying at least one technique, matching
    `marker_rate.corpus_texts()` -- DF over rows the retrieval pool never
    contains would describe a different corpus than the one being tagged.
    """
    docs = []
    for path in CORPUS_PATHS:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if [t for t in row["technique_ids"].split(";") if t]:
                    docs.append(entity_key(row["msg"]))
    return docs


def build(max_n=MAX_NGRAM):
    docs = corpus_documents()
    counts = Counter()
    for doc in docs:
        counts.update(ngrams(tokenize(doc), max_n))
    return counts, len(docs)


def write(path=DF_PATH, max_n=MAX_NGRAM, min_count=2):
    """Writes the DF artifact.

    `min_count=2` drops hapax n-grams. They are ~everything (most 5-grams occur
    once) and every one of them is rare, which is the default answer anyway --
    keeping them would multiply the artifact size to restate the default.
    """
    counts, n_docs = build(max_n)
    kept = {k: c for k, c in counts.items() if c >= min_count}
    blob = {
        "meta": {
            "n_docs": n_docs,
            "max_ngram": max_n,
            "min_count": min_count,
            "n_kept": len(kept),
            "corpora": [os.path.basename(p) for p in CORPUS_PATHS
                        if os.path.exists(p)],
        },
        "counts": kept,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(blob, fh)
    return blob


class DFTable:
    """Read-side lookup: span surface string -> document frequency in [0, 1].

    An n-gram absent from the table is rare by definition (it occurred 0 or 1
    times in the corpus), so `df()` returns 0.0 rather than raising. That makes
    the unseen case the *replaceable* case, which is the intended default:
    replacement is for strings the corpus has no evidence about.
    """

    def __init__(self, path=DF_PATH):
        self.path = path
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{path} not found -- run "
                f"`python -m attack_mapper.entity_ner.df_table` first"
            )
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            blob = json.load(fh)
        self.meta = blob["meta"]
        self.counts = blob["counts"]
        self.n_docs = max(1, int(self.meta["n_docs"]))
        self.max_ngram = int(self.meta["max_ngram"])

    def df(self, text):
        key = " ".join(tokenize(text))
        if not key:
            return 0.0
        return self.counts.get(key, 0) / self.n_docs

    def is_rare(self, text, cutoff):
        """Strictly below the cutoff. A span whose DF equals the cutoff is
        kept, so `cutoff=0.0` disables replacement entirely rather than
        replacing every unseen span -- a usable no-op arm for the sweep."""
        return self.df(text) < cutoff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", nargs="*", default=None,
                    help="probe these strings instead of rebuilding")
    ap.add_argument("--max-ngram", type=int, default=MAX_NGRAM)
    args = ap.parse_args()

    if args.show is not None:
        table = DFTable()
        print(f"artifact: {table.meta['n_docs']} docs, "
              f"{table.meta['n_kept']} n-grams kept\n")
        for s in args.show:
            print(f"  {table.df(s):7.4%}  {s!r}")
        return

    blob = write(max_n=args.max_ngram)
    m = blob["meta"]
    print(f"corpora: {', '.join(m['corpora'])}")
    print(f"documents: {m['n_docs']}")
    print(f"n-grams kept (count >= {m['min_count']}): {m['n_kept']}")
    print(f"wrote {DF_PATH}\n")

    table = DFTable()
    probes = ["SQL", "Injection Attempt", "HTTP", "SMB", "DNS", "RDP",
              "URI", "URL", "UDN", "WordPress", "FortiOS", "Jetty",
              "ASA 5500 Series", "Mimikatz"]
    print("the report's named probes:")
    print(f"  {'DF':>9}  string")
    for s in probes:
        print(f"  {table.df(s):8.4%}  {s}")


if __name__ == "__main__":
    main()
