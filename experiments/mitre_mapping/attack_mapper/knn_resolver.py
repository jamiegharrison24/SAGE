"""
Retrieval over the *labeled corpus* -- replaces `embedder.py`'s zero-shot
similarity against MITRE technique descriptions.

Why this exists: `embedder.py` compared a rule's narrative against MITRE's own
documentation prose ("Adversaries may attempt to get a listing of services
running on remote hosts..."). Detection-rule titles are terse vendor shorthand
("ET SCAN Nmap Scripting Engine User-Agent"); MITRE descriptions are formal
analyst prose. General-purpose sentence embeddings do not bridge that register
gap, which is why that layer measured 6.4-8.4% top-1 in `../archive/results.md`
and 4.5% in the 500-row run (`../findings.md`).

This compares rule text against *other rule text* -- the ~30k ET+Sigma labeled
corpus already used to train `classifier_resolver.py` -- and takes the labels of
the nearest neighbours. Same vocabulary on both sides, and the label comes from
a real vendor-tagged example rather than from matching documentation.

Two details that matter more than the retrieval itself:

**IDF-weighted voting.** Summing neighbour similarity per technique hands the
win to whatever is simply most common in the corpus -- T1190 is roughly a third
of it -- reproducing the hub-collapse every other method in this branch has hit
(`../findings.md`, effort 8). Each neighbour's vote is therefore scaled by
`log(N / (1 + corpus_frequency(technique)))`, so a neighbour voting for a rare
technique counts for more than one voting for the hub. Measured on the 500-row
set: sum-of-similarity predicts T1190 on 49.4% of rows against a true base rate
of 28.5% (macro 16.0%); IDF-weighted predicts it on 29.7% (macro 19.7%) for
effectively the same micro accuracy. The IDF term is what keeps this honest.

**Leakage guard.** 39 of the 500 evaluation signatures appear verbatim in the
training corpus. Exact canonical matches are excluded at query time, otherwise
those rows retrieve themselves and the method scores its own training data.
"""
import csv
import hashlib
import os
from typing import Dict, List, Optional, Tuple

import numpy as np

from .normalize import canonicalize

HERE = os.path.dirname(os.path.abspath(__file__))
ET_CORPUS_PATH = os.path.join(HERE, "data", "et_labeled_corpus.csv")
SIGMA_CORPUS_PATH = os.path.join(HERE, "data", "sigma_labeled_corpus.csv")
CACHE_PATH = os.path.join(HERE, "data", "knn_corpus_embeddings.npz")

_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_K = 10


def _load_corpus() -> Tuple[List[str], List[List[str]]]:
    texts, labels = [], []
    for path in (ET_CORPUS_PATH, SIGMA_CORPUS_PATH):
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                ids = [t for t in row["technique_ids"].split(";") if t]
                if ids:
                    texts.append(canonicalize(row["msg"]))
                    labels.append(ids)
    return texts, labels


def _corpus_fingerprint() -> str:
    """Cheap cache key: path, size and mtime of each corpus file."""
    h = hashlib.sha256()
    for path in (ET_CORPUS_PATH, SIGMA_CORPUS_PATH):
        if os.path.exists(path):
            st = os.stat(path)
            h.update(f"{path}:{st.st_size}:{st.st_mtime_ns}".encode())
    h.update(_MODEL_NAME.encode())
    return h.hexdigest()


class KnnResolver:
    """Nearest-neighbour retrieval over the labeled ET+Sigma corpus.

    Embedding ~30k rows takes ~45s, so the matrix is cached next to the corpus
    and reused whenever the corpus files and model are unchanged.
    """

    def __init__(self, k: int = DEFAULT_K):
        from sentence_transformers import SentenceTransformer  # heavy import, deferred

        self.k = k
        self.texts, self.labels = _load_corpus()
        if not self.texts:
            raise RuntimeError(
                f"no labeled corpus found at {ET_CORPUS_PATH} or {SIGMA_CORPUS_PATH}"
            )
        self.model = SentenceTransformer(_MODEL_NAME)
        self._embeddings = self._load_or_build_embeddings()
        self._canon = np.array(self.texts)

        freq: Dict[str, int] = {}
        for ids in self.labels:
            for tid in ids:
                freq[tid] = freq.get(tid, 0) + 1
        n = len(self.labels)
        # Precomputed IDF weight per technique -- see module docstring.
        self._idf = {tid: float(np.log(n / (1 + c))) for tid, c in freq.items()}

    def _load_or_build_embeddings(self) -> np.ndarray:
        fingerprint = _corpus_fingerprint()
        if os.path.exists(CACHE_PATH):
            try:
                cached = np.load(CACHE_PATH, allow_pickle=False)
                if str(cached["fingerprint"]) == fingerprint:
                    return cached["embeddings"]
            except Exception:
                pass  # unreadable or stale cache -- rebuild rather than fail
        emb = self.model.encode(
            self.texts, convert_to_numpy=True, show_progress_bar=False, batch_size=256
        )
        emb /= np.maximum(np.linalg.norm(emb, axis=1, keepdims=True), 1e-9)
        try:
            np.savez(CACHE_PATH, embeddings=emb, fingerprint=np.array(fingerprint))
        except Exception:
            pass  # cache is an optimisation, not a requirement
        return emb

    def predict(self, text: str, top_k: int = 3) -> List[dict]:
        """Returns [{technique_id, confidence, support, evidence}], best first.

        `confidence` MUST be monotonic in the IDF-weighted vote, because
        `reasoner.py` re-sorts every candidate by confidence and would
        otherwise discard the ranking computed here. An earlier version
        returned mean neighbour similarity instead, which is a different
        quantity -- the reasoner then silently reordered candidates and threw
        away the IDF weighting that keeps this layer off the T1190 hub,
        costing ~3 points of top-1 accuracy before it was caught.

        So confidence = vote_share * row_quality, where `vote_share` is this
        technique's share of the total IDF-weighted vote (preserving rank
        within the row) and `row_quality` is the single best neighbour
        similarity for the row (so a query with no close labeled example
        scores low overall, and rows stay comparable to other sources).
        """
        canon = canonicalize(text)
        query = self.model.encode([canon], convert_to_numpy=True, show_progress_bar=False)[0]
        norm = float(np.linalg.norm(query))
        if norm == 0:
            return []
        query = query / norm

        sims = self._embeddings @ query
        # Leakage guard -- see module docstring.
        sims[self._canon == canon] = -1.0

        k = min(self.k, len(sims))
        idx = np.argpartition(-sims, k - 1)[:k]
        idx = idx[np.argsort(-sims[idx])]

        votes: Dict[str, float] = {}
        support: Dict[str, List[float]] = {}
        nearest: Dict[str, str] = {}
        for j in idx:
            sim = float(sims[j])
            if sim <= 0:
                continue
            for tid in self.labels[j]:
                votes[tid] = votes.get(tid, 0.0) + sim * self._idf.get(tid, 1.0)
                support.setdefault(tid, []).append(sim)
                nearest.setdefault(tid, self.texts[j])

        if not votes:
            return []

        total_vote = sum(votes.values())
        row_quality = max(max(s) for s in support.values())

        ranked = sorted(votes.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        out = []
        for tid, weight in ranked:
            sup = support[tid]
            out.append({
                "technique_id": tid,
                "confidence": float(weight / total_vote * row_quality),
                "support": len(sup),
                "evidence": (
                    f"{len(sup)} of {k} nearest labeled rules "
                    f"(vote share {weight / total_vote:.0%}, closest neighbour "
                    f"{max(sup):.2f}); closest: \"{nearest[tid][:80]}\""
                ),
            })
        return out


_singleton: Optional[KnnResolver] = None


def get_default_knn() -> KnnResolver:
    global _singleton
    if _singleton is None:
        _singleton = KnnResolver()
    return _singleton
