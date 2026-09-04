"""
Stacks effort 4 (../sigma_corpus, the ET+Sigma broadened training corpus)
onto effort 3 (this pipeline) as a new candidate source -- the combination
`../STATUS.md` flagged as untried after both were evaluated in isolation
(effort 3: 48.8% top-1 from SAGE-internal signal; effort 4: 38.0% top-1 from
a broadened Tier 2 classifier, +3.8 points over ET-only and a big
hub-collapse reduction).

Trains live (not a static lookup against the precomputed 773-signature
`tier2_combined_predictions.csv`) by importing `tier2_classifier.py`'s
fit/score functions directly, so this resolves *any* rule text at pipeline
runtime, not just the 773 signatures that happen to already be in
`ground_truth_signatures.csv`. Training cost is paid once per process
(~1-2 min for ~29k rows / 397 classes), same lifecycle as `embedder.py`'s
one-time MiniLM embedding pass.

Placed as a candidate source *below* declared/ioc_alias/bridge_table
(all higher-precision, per `../findings.md`'s source breakdown) and *above*
raw zero-shot embedding similarity (Layer A, measured at 0% precision in
that same breakdown) -- a supervised classifier trained on real ATT&CK-
tagged rule text is a strictly more informed fallback than untrained
cosine similarity against technique descriptions.
"""
import os
import sys
from typing import List, Optional

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
TIERED_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "tiered_approach"))
SIGMA_CORPUS_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "sigma_corpus"))
if TIERED_DIR not in sys.path:
    sys.path.insert(0, TIERED_DIR)

from normalize import canonicalize  # noqa: E402
from tier2_classifier import decision_scores, fit_dual_ovr  # noqa: E402
from sklearn.preprocessing import MultiLabelBinarizer  # noqa: E402

ET_CORPUS_PATH = os.path.join(TIERED_DIR, "et_labeled_corpus.csv")
SIGMA_CORPUS_PATH = os.path.join(SIGMA_CORPUS_DIR, "sigma_labeled_corpus.csv")


def _load_corpus(path: str):
    import csv
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    texts = [canonicalize(r["msg"]) for r in rows]
    labels = [tuple(r["technique_ids"].split(";")) if r["technique_ids"] else () for r in rows]
    return texts, labels


class ClassifierResolver:
    """Live-trained ET+Sigma Tier 2 classifier, wrapped for per-rule
    prediction. Only fires when the model actually votes positive for a
    label (decision_function score > 0) -- a negative top-1 score is just
    "least bad of all rejected labels", not a real signal."""

    def __init__(self):
        texts = []
        labels = []
        if os.path.exists(ET_CORPUS_PATH):
            corpus_texts, corpus_labels = _load_corpus(ET_CORPUS_PATH)
            texts += corpus_texts
            labels += corpus_labels
        if os.path.exists(SIGMA_CORPUS_PATH):
            corpus_texts, corpus_labels = _load_corpus(SIGMA_CORPUS_PATH)
            texts += corpus_texts
            labels += corpus_labels
        if not texts:
            raise RuntimeError(
                f"no training corpus found at {ET_CORPUS_PATH} or {SIGMA_CORPUS_PATH}"
            )

        self.mlb = MultiLabelBinarizer()
        Y = self.mlb.fit_transform(labels)
        self.char_vec, self.word_vec, self.clf_c, self.clf_w = fit_dual_ovr(texts, Y)
        self.corpus_size = len(texts)

    def predict(self, text: str, top_k: int = 3) -> List[dict]:
        canon = canonicalize(text)
        scores = decision_scores([canon], self.char_vec, self.word_vec, self.clf_c, self.clf_w)[0]
        top_idx = np.argsort(-scores)[:top_k]
        return [
            {"technique_id": self.mlb.classes_[i], "score": float(scores[i])}
            for i in top_idx
            if scores[i] > 0
        ]


_singleton: Optional[ClassifierResolver] = None


def get_default_classifier() -> ClassifierResolver:
    global _singleton
    if _singleton is None:
        _singleton = ClassifierResolver()
    return _singleton
