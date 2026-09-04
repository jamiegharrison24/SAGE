"""
Tier 2: multi-label classifier trained on the Tier-0 free corpus
(et_labeled_corpus.csv, ~26.6k ET rule messages with real vendor-authored
mitre_technique_id/tactic_id metadata -- independent of our own 773-signature
ground truth, so there's no circularity in using it as training data).

Tactic-first hierarchy: a 14-class tactic classifier (easier, high accuracy)
and a technique classifier, trained and reported separately. Two TF-IDF
representations (char n-gram, robust to vendor mangling; word n-gram) are
each fit with a OneVsRestClassifier(LinearSVC) and their decision scores
averaged, per the "train both, they fail differently" heuristic.

Known structural ceiling (see corpus_stats.py output): the ET metadata
vocabulary only covers 45 distinct top-level techniques (no sub-techniques),
dominated by T1190/T1071/T1568/T1189/T1566 (initial-access and C2). A
signature whose true label falls outside that 45-technique set can never be
predicted correctly by this tier, by construction -- it will fall through to
Tier 3. This mirrors the "filtered candidate list has a structural ceiling"
finding in ../results.md, and is reported rather than absorbed.

Usage: python tier2_classifier.py
Writes tier2_predictions.csv for every one of our 773 signatures (score.py-
style top-3 technique columns + a predicted_tactic column), and
tier2_cv_report.txt (5-fold cross-val precision/recall on the training
corpus itself, not on our 773 -- the honest generalization number).
"""
import csv
import os
import sys

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import LinearSVC
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import KFold
from sklearn.metrics import precision_recall_fscore_support

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import canonicalize  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS_PATH = os.path.join(HERE, "et_labeled_corpus.csv")
GT_PATH = os.path.join(ROOT, "ground_truth_signatures.csv")
OUT_PATH = os.path.join(HERE, "tier2_predictions.csv")
CV_REPORT_PATH = os.path.join(HERE, "tier2_cv_report.md")


def load_corpus():
    rows = list(csv.DictReader(open(CORPUS_PATH, encoding="utf-8")))
    texts = [canonicalize(r["msg"]) for r in rows]
    tech_labels = [tuple(r["technique_ids"].split(";")) if r["technique_ids"] else () for r in rows]
    tactic_labels = [tuple(r["tactic_ids"].split(";")) if r["tactic_ids"] else () for r in rows]
    return texts, tech_labels, tactic_labels


def fit_dual_ovr(texts, y):
    """Fit char-ngram and word-ngram TF-IDF + OneVsRest(LinearSVC), return
    (char_vec, word_vec, char_clf, word_clf, classes_)."""
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)
    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=2)
    Xc = char_vec.fit_transform(texts)
    Xw = word_vec.fit_transform(texts)
    clf_c = OneVsRestClassifier(LinearSVC(class_weight="balanced"), n_jobs=-1)
    clf_w = OneVsRestClassifier(LinearSVC(class_weight="balanced"), n_jobs=-1)
    clf_c.fit(Xc, y)
    clf_w.fit(Xw, y)
    return char_vec, word_vec, clf_c, clf_w


def decision_scores(texts, char_vec, word_vec, clf_c, clf_w):
    Xc = char_vec.transform(texts)
    Xw = word_vec.transform(texts)
    return (clf_c.decision_function(Xc) + clf_w.decision_function(Xw)) / 2.0


def cross_val_report(texts, y_tuples, mlb, name, k=5):
    Y = mlb.transform(y_tuples)
    texts = np.array(texts, dtype=object)
    kf = KFold(n_splits=k, shuffle=True, random_state=0)
    all_true, all_pred = [], []
    for train_idx, test_idx in kf.split(texts):
        char_vec, word_vec, clf_c, clf_w = fit_dual_ovr(list(texts[train_idx]), Y[train_idx])
        scores = decision_scores(list(texts[test_idx]), char_vec, word_vec, clf_c, clf_w)
        pred = (scores > 0).astype(int)
        all_true.append(Y[test_idx])
        all_pred.append(pred)
    Y_true = np.vstack(all_true)
    Y_pred = np.vstack(all_pred)
    p, r, f1, support = precision_recall_fscore_support(Y_true, Y_pred, average=None, zero_division=0)
    micro_p, micro_r, micro_f1, _ = precision_recall_fscore_support(Y_true, Y_pred, average="micro", zero_division=0)
    lines = [f"=== {name}: {k}-fold CV, per-class (labels with support>0) ==="]
    for cls, pp, rr, ff, s in sorted(zip(mlb.classes_, p, r, f1, support), key=lambda t: -t[4]):
        if s == 0:
            continue
        lines.append(f"  {cls:10s} support={s:5d}  precision={pp:.3f}  recall={rr:.3f}  f1={ff:.3f}")
    lines.append(f"  MICRO-AVG  precision={micro_p:.3f}  recall={micro_r:.3f}  f1={micro_f1:.3f}")
    return "\n".join(lines)


def main():
    texts, tech_labels, tactic_labels = load_corpus()
    print(f"training corpus: {len(texts)} rows")

    mlb_tech = MultiLabelBinarizer()
    mlb_tech.fit(tech_labels)
    mlb_tactic = MultiLabelBinarizer()
    mlb_tactic.fit(tactic_labels)

    with open(CV_REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(cross_val_report(texts, tactic_labels, mlb_tactic, "TACTIC classifier") + "\n\n")
        fh.write(cross_val_report(texts, tech_labels, mlb_tech, "TECHNIQUE classifier") + "\n")
    print(f"Wrote {CV_REPORT_PATH}")

    # Fit final models on the full corpus for prediction on our 773.
    Y_tech = mlb_tech.transform(tech_labels)
    Y_tactic = mlb_tactic.transform(tactic_labels)
    tech_char_vec, tech_word_vec, tech_clf_c, tech_clf_w = fit_dual_ovr(texts, Y_tech)
    tac_char_vec, tac_word_vec, tac_clf_c, tac_clf_w = fit_dual_ovr(texts, Y_tactic)

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]
    canon_sigs = [canonicalize(s) for s in sigs]

    tech_scores = decision_scores(canon_sigs, tech_char_vec, tech_word_vec, tech_clf_c, tech_clf_w)
    tac_scores = decision_scores(canon_sigs, tac_char_vec, tac_word_vec, tac_clf_c, tac_clf_w)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "signature",
            "predicted_technique_1", "score_1",
            "predicted_technique_2", "score_2",
            "predicted_technique_3", "score_3",
            "predicted_tactic_1", "tactic_score_1",
        ])
        for sig, trow, tarow in zip(sigs, tech_scores, tac_scores):
            top_tech_idx = np.argsort(-trow)[:3]
            cells = []
            for idx in top_tech_idx:
                cells += [mlb_tech.classes_[idx], f"{trow[idx]:.4f}"]
            top_tactic_idx = int(np.argmax(tarow))
            row = [sig] + cells + [mlb_tactic.classes_[top_tactic_idx], f"{tarow[top_tactic_idx]:.4f}"]
            w.writerow(row)
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
