"""
Tier 2b: same architecture as tier2_classifier.py (multi-label
OneVsRestClassifier(LinearSVC), trained on the same 26.6k et_labeled_corpus.csv,
predicting on the same 773 signatures) but with the TF-IDF features swapped
for pretrained MiniLM sentence embeddings (sentence-transformers/all-MiniLM-L6-v2,
the same model used for "method 3/4" in ../results.md) -- a controlled
one-variable swap to test whether semantic embeddings fix the T1190 hub-collapse
that tier2_classifier.py's bag-of-words features can't (see
tier2_vs_audit_findings.md: it confidently mis-called a client-side browser
exploit T1190 because the words overlapped, with no notion of *meaning*).

Only one embedding representation is used (no char/word duality -- that
distinction existed in the TF-IDF version specifically to be robust to
vendor text mangling; a single pretrained embedding already captures
subword/character info via its WordPiece tokenizer).

Usage: python tier2_classifier_embed.py
Writes tier2_embed_predictions.csv and tier2_embed_cv_report.md.
"""
import csv
import os
import sys

import numpy as np
from sentence_transformers import SentenceTransformer
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
OUT_PATH = os.path.join(HERE, "tier2_embed_predictions.csv")
CV_REPORT_PATH = os.path.join(HERE, "tier2_embed_cv_report.md")
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def load_corpus():
    rows = list(csv.DictReader(open(CORPUS_PATH, encoding="utf-8")))
    texts = [canonicalize(r["msg"]) for r in rows]
    tech_labels = [tuple(r["technique_ids"].split(";")) if r["technique_ids"] else () for r in rows]
    tactic_labels = [tuple(r["tactic_ids"].split(";")) if r["tactic_ids"] else () for r in rows]
    return texts, tech_labels, tactic_labels


def embed(model, texts, batch_size=128):
    return model.encode(texts, batch_size=batch_size, show_progress_bar=True,
                         convert_to_numpy=True, normalize_embeddings=True)


def fit_ovr(X, y):
    clf = OneVsRestClassifier(LinearSVC(class_weight="balanced"), n_jobs=-1)
    clf.fit(X, y)
    return clf


def cross_val_report(X, y_tuples, mlb, name, k=5):
    Y = mlb.transform(y_tuples)
    kf = KFold(n_splits=k, shuffle=True, random_state=0)
    all_true, all_pred = [], []
    for train_idx, test_idx in kf.split(X):
        clf = fit_ovr(X[train_idx], Y[train_idx])
        scores = clf.decision_function(X[test_idx])
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

    print(f"embedding {len(texts)} corpus texts with {MODEL_NAME} ...")
    model = SentenceTransformer(MODEL_NAME)
    X = embed(model, texts)

    mlb_tech = MultiLabelBinarizer()
    mlb_tech.fit(tech_labels)
    mlb_tactic = MultiLabelBinarizer()
    mlb_tactic.fit(tactic_labels)

    with open(CV_REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(cross_val_report(X, tactic_labels, mlb_tactic, "TACTIC classifier") + "\n\n")
        fh.write(cross_val_report(X, tech_labels, mlb_tech, "TECHNIQUE classifier") + "\n")
    print(f"Wrote {CV_REPORT_PATH}")

    Y_tech = mlb_tech.transform(tech_labels)
    Y_tactic = mlb_tactic.transform(tactic_labels)
    tech_clf = fit_ovr(X, Y_tech)
    tac_clf = fit_ovr(X, Y_tactic)

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]
    canon_sigs = [canonicalize(s) for s in sigs]
    print(f"embedding {len(canon_sigs)} target signatures ...")
    X_sigs = embed(model, canon_sigs)

    tech_scores = tech_clf.decision_function(X_sigs)
    tac_scores = tac_clf.decision_function(X_sigs)

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
