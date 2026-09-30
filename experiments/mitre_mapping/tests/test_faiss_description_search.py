"""Regression tests for FAISS-based MITRE description retrieval."""
import unittest

import numpy as np

from experiments.mitre_mapping.attack_mapper.map_alerts_sentence_transformers import (
    search_candidates,
)


class FaissDescriptionSearchTests(unittest.TestCase):
    def test_search_candidates_matches_dense_cosine_similarity(self):
        candidate_embeddings = np.ascontiguousarray(
            [[1.0, 0.0], [0.0, 1.0], [0.8, 0.6]], dtype=np.float32
        )
        query_embeddings = np.ascontiguousarray([[0.6, 0.8]], dtype=np.float32)
        candidates = [
            {"code": "T1000", "name": "Technique", "type": "technique"},
            {"code": "TA0001", "name": "Tactic", "type": "tactic"},
            {"code": "T1001", "name": "Other technique", "type": "technique"},
        ]

        dense_scores = query_embeddings @ candidate_embeddings.T
        dense_order = np.argsort(-dense_scores[0])[:2]
        results = search_candidates(
            ["alert text"], candidates, query_embeddings, candidate_embeddings, top_k=2
        )

        self.assertEqual([candidate["code"] for _, candidate, _ in results],
                         [candidates[index]["code"] for index in dense_order])
        np.testing.assert_allclose(
            [score for _, _, score in results], dense_scores[0, dense_order]
        )
        self.assertEqual(results[0][1]["code"], "T1001")


if __name__ == "__main__":
    unittest.main()