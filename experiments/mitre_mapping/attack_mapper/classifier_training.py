"""
Dual char/word TF-IDF + OneVsRestClassifier(LinearSVC) training, used by
`classifier_resolver.py` to train the ET+Sigma technique classifier live.

Own copy inside this package (the reusable `fit_dual_ovr`/`decision_scores`
functions originally in ../archive/tiered_approach/tier2_classifier.py,
minus that file's own corpus-loading/CV-report/CLI bits, which stay archived
since they're specific to that standalone script) so this package has no
imports reaching outside its own tree -- see ../STATUS.md.

Two TF-IDF representations (char n-gram, robust to vendor mangling; word
n-gram) are each fit separately and their decision scores averaged, per the
"train both, they fail differently" heuristic from
../archive/tiered_approach/strategy.md.
"""
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import LinearSVC


def fit_dual_ovr(texts, y):
    """Fit char-ngram and word-ngram TF-IDF + OneVsRest(LinearSVC), return
    (char_vec, word_vec, char_clf, word_clf)."""
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
