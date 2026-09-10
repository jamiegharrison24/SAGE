"""
Stacks effort 4 (the ET+Sigma broadened training corpus, `sigma_corpus/`)
onto effort 3 (this pipeline) as a new candidate source -- the combination
`../STATUS.md` flagged as untried after both were evaluated in isolation
(effort 3: 48.8% top-1 from SAGE-internal signal; effort 4: 38.0% top-1 from
a broadened Tier 2 classifier, +3.8 points over ET-only and a big
hub-collapse reduction).

Trains live (not a static lookup against a precomputed prediction table) by
using `classifier_training.py`'s fit/score functions directly, so this
resolves *any* rule text at pipeline runtime, not just signatures that
happen to already be in a fixed ground-truth list. Training cost is paid
once per process (~1-2 min for ~29k rows / 397 classes), same lifecycle as
`knn_resolver.py`'s one-time corpus embedding pass.

Placed as a candidate source *below* declared/ioc_alias (both higher-precision,
per `../findings.md`'s source breakdown) and *above* `knn_resolver.py`'s
nearest-neighbour retrieval, which measured 36.3% micro standalone on the
500-row set versus this classifier's 42.7% on its own pool.
"""
import csv
import os
from typing import List, Optional

import numpy as np
from sklearn.preprocessing import MultiLabelBinarizer

from .classifier_training import decision_scores, fit_dual_ovr
from .normalize import canonicalize

HERE = os.path.dirname(os.path.abspath(__file__))
ET_CORPUS_PATH = os.path.join(HERE, "data", "et_labeled_corpus.csv")
SIGMA_CORPUS_PATH = os.path.join(HERE, "data", "sigma_labeled_corpus.csv")


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
    "least bad of all rejected labels", not a real signal.

    `prior_alpha` subtracts a class-frequency term from the decision scores,
    so a common technique needs a stronger margin to win than a rare one.
    Without it the classifier predicted T1190 on 56.2% of the rows it answered
    against a 28.5% true rate -- the same hub-collapse `knn_resolver.py`'s
    IDF weighting exists to prevent, and the same one that made effort 8's
    qwen2.5 run look like a win (`../findings.md`). Measured on the 500-row
    set, sweeping alpha end to end:

        alpha  micro   macro   T1190 share (true 28.5%)
        0.0    39.0%   20.8%   39.5%
        0.5    38.8%   21.1%   33.5%     <- default: calibration for ~free
        1.0    37.8%   21.4%   28.5%     <- exactly calibrated, -1.2 micro

    0.5 is the default because it costs 0.2 points of micro for a 6-point
    calibration gain. Raise toward 1.0 if honest per-technique behaviour
    matters more than top-line accuracy for a given use.
    """

    def __init__(self, prior_alpha: float = 0.5):
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

        # Class-frequency prior, normalised to [0, 1] so `prior_alpha` is
        # interpretable on the same scale regardless of corpus size.
        self.prior_alpha = prior_alpha
        counts = Y.sum(axis=0).astype(float)
        prior = np.log(counts + 1)
        self._prior = prior / prior.max() if prior.max() > 0 else prior

    def predict(self, text: str, top_k: int = 3) -> List[dict]:
        canon = canonicalize(text)
        scores = decision_scores([canon], self.char_vec, self.word_vec, self.clf_c, self.clf_w)[0]
        scores = scores - self.prior_alpha * self._prior
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
