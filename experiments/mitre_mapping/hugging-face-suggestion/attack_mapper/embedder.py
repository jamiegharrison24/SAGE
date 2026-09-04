"""
Layer A: zero-shot embedding similarity between a rule's narrative and every
ATT&CK technique description.

Known weak on this corpus -- `../results.md` methods 1-4 already ran exactly
this (MiniLM/ATTACK-BERT, full 697-technique list, cosine similarity) and
got 6.4-8.4% top-1 / 24.9-26.3% right-tactic. It is kept here anyway as the
lowest-priority fallback candidate source (see `config.Settings.
embedding_confidence_cap`) for rules IoC/bridge/declared sources say nothing
about -- not because it is expected to be strong on its own.

The HF sketch's `TechniqueEmbedder._precompute_techniques` was `pass`,
leaving `find_similar_techniques` to silently iterate an empty dict and
return `[]`. Fixed here by actually embedding every technique's
`MitreAttackClient.technique_text()` on construction.
"""
from typing import Dict, List

import numpy as np

from .mitre_client import MitreAttackClient

_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


class TechniqueEmbedder:
    def __init__(self, mitre_client: MitreAttackClient, model_name: str = _MODEL_NAME):
        from sentence_transformers import SentenceTransformer  # heavy import, deferred

        self.mitre = mitre_client
        self.model = SentenceTransformer(model_name)
        self._technique_ids: List[str] = sorted(mitre_client.get_all_techniques().keys())
        texts = [mitre_client.technique_text(tid) for tid in self._technique_ids]
        embeddings = self.model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self._technique_embeddings = embeddings / norms

    def find_similar(self, narrative_text: str, top_k: int = 5) -> List[Dict[str, object]]:
        query = self.model.encode([narrative_text], convert_to_numpy=True, show_progress_bar=False)[0]
        norm = np.linalg.norm(query)
        if norm == 0:
            return []
        query = query / norm
        sims = self._technique_embeddings @ query
        top_idx = np.argsort(-sims)[:top_k]
        return [
            {"technique_id": self._technique_ids[i], "similarity": float(sims[i])}
            for i in top_idx
        ]
