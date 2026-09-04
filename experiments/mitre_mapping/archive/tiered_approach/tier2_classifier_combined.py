"""
Tier 2 variant: same architecture as `tier2_classifier.py` (dual char/word
TF-IDF + OneVsRestClassifier(LinearSVC), decision scores averaged), but
trained on `et_labeled_corpus.csv` **plus**
`../sigma_corpus/sigma_labeled_corpus.csv` concatenated.

This directly tests `embedding_swap_findings.md`'s conclusion that Tier 2's
weak accuracy is a training-corpus class-imbalance problem, not a feature-
representation problem, and its specific recommendation to fix it by folding
in Sigma's ATT&CK-tagged rules. `../sigma_corpus/findings.md` has the corpus
stats: ET alone covers 45 techniques (top 5 = 81.3% of rows, T1203 has 1
example); combined with Sigma's 2,798 rows it's 397 techniques (T1203 -> 20
examples), with Sigma covering 352 techniques ET never tags at all.

Usage: python tier2_classifier_combined.py
Requires ../sigma_corpus/sigma_labeled_corpus.csv (run
../sigma_corpus/build_corpus.py first).
Writes tier2_combined_predictions.csv and tier2_combined_cv_report.md.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import canonicalize  # noqa: E402
from tier2_classifier import (  # noqa: E402
    cross_val_report, decision_scores, fit_dual_ovr,
)
from sklearn.preprocessing import MultiLabelBinarizer  # noqa: E402
import numpy as np  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ET_CORPUS_PATH = os.path.join(HERE, "et_labeled_corpus.csv")
SIGMA_CORPUS_PATH = os.path.join(ROOT, "sigma_corpus", "sigma_labeled_corpus.csv")
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
OUT_PATH = os.path.join(HERE, "tier2_combined_predictions.csv")
CV_REPORT_PATH = os.path.join(HERE, "tier2_combined_cv_report.md")


def load_corpus(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    texts = [canonicalize(r["msg"]) for r in rows]
    tech_labels = [tuple(r["technique_ids"].split(";")) if r["technique_ids"] else () for r in rows]
    return texts, tech_labels


def main():
    et_texts, et_tech = load_corpus(ET_CORPUS_PATH)
    sigma_texts, sigma_tech = load_corpus(SIGMA_CORPUS_PATH)
    texts = et_texts + sigma_texts
    tech_labels = et_tech + sigma_tech
    print(f"combined training corpus: {len(texts)} rows ({len(et_texts)} ET + {len(sigma_texts)} Sigma)")

    mlb_tech = MultiLabelBinarizer()
    mlb_tech.fit(tech_labels)
    print(f"distinct techniques in combined corpus: {len(mlb_tech.classes_)}")

    with open(CV_REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(cross_val_report(texts, tech_labels, mlb_tech, "TECHNIQUE classifier (ET+Sigma)") + "\n")
    print(f"Wrote {CV_REPORT_PATH}")

    Y_tech = mlb_tech.transform(tech_labels)
    char_vec, word_vec, clf_c, clf_w = fit_dual_ovr(texts, Y_tech)

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]
    canon_sigs = [canonicalize(s) for s in sigs]
    scores = decision_scores(canon_sigs, char_vec, word_vec, clf_c, clf_w)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "predicted_technique_1", "score_1",
                    "predicted_technique_2", "score_2", "predicted_technique_3", "score_3"])
        for sig, row in zip(sigs, scores):
            top_idx = np.argsort(-row)[:3]
            cells = []
            for idx in top_idx:
                cells += [mlb_tech.classes_[idx], f"{row[idx]:.4f}"]
            w.writerow([sig] + cells)
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
