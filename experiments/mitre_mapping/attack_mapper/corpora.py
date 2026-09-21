"""
Single source of truth for the labeled (rule text -> ATT&CK technique)
training corpora.

`classifier_resolver.py` trains on these and `knn_resolver.py` retrieves
against them, so the list has to stay identical in both -- and inside
`knn_resolver` it is read twice (once to load rows, once to fingerprint the
cached embedding matrix). A path added to the loader but not the fingerprint
yields a stale cache with N_old embedding rows against N_new corpus rows,
which silently misaligns the leakage mask rather than raising. Hence one
tuple, imported everywhere.

Each corpus is `msg,technique_ids,tactic_ids`, technique IDs `;`-joined.
See ../STATUS.md for how each was built and what it contributes:

| corpus  | rows   | distinct techniques | top-5 share | in use |
|---------|-------:|--------------------:|------------:|--------|
| ET      | 26,644 |                  45 |       81.3% | yes    |
| Sigma   |  3,289 |                 398 |       23.7% | yes    |
| Elastic |  1,892 |                 444 |       15.3% | yes    |
| Splunk  |  2,140 |                 376 |       15.1% | **no** |

Splunk is built and on disk but deliberately not loaded -- see
`splunk_corpus/findings.md`. Measured on top of Elastic it bought +0.5 micro
(2 rows of 397, noise on a set with 208 reviewer-verdicted rows) while costing 0.4
macro, and the 20 top-1 rows its own retrieved neighbours won scored 0/20.
Re-enable by adding it to the tuple below; the corpus and its builder are
kept so that stays a one-line experiment.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")

CORPUS_PATHS = (
    os.path.join(DATA_DIR, "et_labeled_corpus.csv"),
    os.path.join(DATA_DIR, "sigma_labeled_corpus.csv"),
    os.path.join(DATA_DIR, "elastic_labeled_corpus.csv"),
    # effort 18: the observed-alert signatures, labelled to complete technique
    # coverage of the three alert datasets. Disjoint from the eval set by
    # construction (verified 0 overlap) -- these are signatures that fire in
    # the data but were never drawn into the 500-row labelling frame.
    os.path.join(DATA_DIR, "alert_labeled_corpus.csv"),
)

# ORACLE MODE (env: ATTACK_MAPPER_ORACLE=1) swaps effort 19's clean alert
# corpus for the 445-row oracle build, which INCLUDES the eval set's own
# labels. That is deliberate train/test contamination: its purpose is to give
# the downstream AIF-vs-ATT&CK attack-graph study a mapper that works on this
# data, which that study assumes rather than measures. Any accuracy number
# produced under this flag is meaningless as mapper accuracy and must never
# be quoted as one -- effort 19's default corpus is the measured configuration.
if os.environ.get("ATTACK_MAPPER_ORACLE") == "1":
    CORPUS_PATHS = tuple(
        os.path.join(DATA_DIR, "alert_oracle_corpus.csv")
        if p.endswith("alert_labeled_corpus.csv") else p
        for p in CORPUS_PATHS
    )


def corpus_name(path: str) -> str:
    """"…/sigma_labeled_corpus.csv" -> "sigma" -- for per-source reporting."""
    return os.path.basename(path).replace("_labeled_corpus.csv", "")
