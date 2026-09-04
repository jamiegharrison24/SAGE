"""
Tier 3: similarity fallback for anything Tier 2 doesn't confidently resolve.

TF-IDF cosine similarity (word 1-2gram) between the signature text and a
corpus built from each technique's name + description, over the FULL live
technique corpus (697 non-deprecated/non-revoked techniques -- not the
45-technique Tier-2 vocabulary), so this tier's job is specifically to catch
signatures whose true label sits outside what ET's own metadata vocabulary
ever tags.

This is deliberately the same family of approach as methods 1-4 in
../results.md (embedding/TF-IDF similarity against technique descriptions),
which scored 5-8% top-1 there -- expected to be weak here too. It exists as
a last-resort fallback with top-5 candidates surfaced for Tier 4 human
review, not as a claimed accurate tier.

Usage: python tier3_similarity.py
Writes tier3_predictions.csv (top-5 techniques + cosine score) for all 773
signatures (the orchestrator decides which rows actually get used).
"""
import csv
import os
import sys

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import canonicalize  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
OUT_PATH = os.path.join(HERE, "tier3_predictions.csv")

sys.path.insert(0, ROOT)
import attack_data  # noqa: E402


def main():
    objs = attack_data.load_bundle()
    techniques = attack_data.load_techniques(objs)  # {tid: attack_pattern_obj}
    tids = sorted(techniques.keys())
    corpus_texts = []
    for tid in tids:
        ap = techniques[tid]
        text = " ".join([
            ap.get("name", ""),
            ap.get("description", ""),
            ap.get("x_mitre_detection", "") or "",
        ])
        corpus_texts.append(canonicalize(text))

    vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=1, max_df=0.6)
    corpus_matrix = vec.fit_transform(corpus_texts)

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]
    sig_texts = [canonicalize(s) for s in sigs]
    sig_matrix = vec.transform(sig_texts)

    sims = cosine_similarity(sig_matrix, corpus_matrix)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "signature",
            "predicted_technique_1", "score_1",
            "predicted_technique_2", "score_2",
            "predicted_technique_3", "score_3",
            "predicted_technique_4", "score_4",
            "predicted_technique_5", "score_5",
        ])
        for sig, row in zip(sigs, sims):
            top5 = np.argsort(-row)[:5]
            cells = []
            for idx in top5:
                cells += [tids[idx], f"{row[idx]:.4f}"]
            w.writerow([sig] + cells)
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
