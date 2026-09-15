"""Replace-mode entity normalisation (REPORT.md §8 item 7).

These cover the invariants that fail *silently* -- each one produces a
plausible accuracy number rather than an error, so a regression here would be
read as an experimental result rather than a bug.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from attack_mapper import entity_tagger as et  # noqa: E402


class FakeDF:
    """Stands in for the measured DF table so these tests do not depend on a
    built artifact. Values mirror the real measurements."""

    TABLE = {"sql": 0.1206, "injection attempt": 0.1202, "http": 0.1222,
             "nmap": 0.0002, "jetty": 0.0, "asa 5500 series": 0.0}

    def df(self, text):
        return self.TABLE.get(" ".join(text.lower().split()), 0.0)

    def is_rare(self, text, cutoff):
        return self.df(text) < cutoff


TEXT = "Nmap scan of SQL Injection Attempt on Jetty"
NMAP, SQL, INJ, JETTY = (0, 4), (13, 16), (17, 34), (38, 43)


def test_frequent_spans_survive_replacement():
    """The whole point of the DF gate: `SQL` and `Injection Attempt` carry the
    technique signal, so replacing them destroys what is being classified."""
    out, replaced, kept = et.replace_spans(
        TEXT, [NMAP, SQL, INJ, JETTY], FakeDF(), 0.01)
    assert "SQL" in out and "Injection Attempt" in out
    assert replaced == 2 and kept == 2


def test_rare_spans_are_replaced():
    out, _, _ = et.replace_spans(TEXT, [NMAP, JETTY], FakeDF(), 0.01)
    assert "Nmap" not in out and "Jetty" not in out
    assert out.count(et.MARKER) == 2


def test_zero_cutoff_is_an_exact_no_op():
    """Arm zero of the sweep must reproduce untagged text byte-for-byte,
    otherwise the control is not a control."""
    out, replaced, kept = et.replace_spans(
        TEXT, [NMAP, SQL, INJ, JETTY], FakeDF(), 0.0)
    assert out == TEXT
    assert replaced == 0 and kept == 4


def test_replacement_makes_differing_rules_alike():
    """Effort 13's diagnosis of why augment failed: only replacement collapses
    the distinction between two rules that differ solely in a rare entity."""
    a, _, _ = et.replace_spans("nmap scan", [(0, 4)], FakeDF(), 0.01)
    b, _, _ = et.replace_spans("jetty scan", [(0, 5)], FakeDF(), 0.01)
    assert a == b == f"{et.MARKER} scan"


def test_augment_path_is_unchanged():
    """Effort 13's 19.4%/21.3% numbers must stay reproducible for the
    comparison to mean anything, so replace-mode is a second path."""
    assert et.inject_markers("nmap scan", [(0, 4)]) == f"nmap {et.MARKER}  scan"


def test_offsets_stay_valid_under_length_change():
    """Replacement changes span lengths, so a left-to-right rewrite would
    corrupt every later offset. Multi-span text catches it."""
    out, replaced, _ = et.replace_spans(
        "ASA 5500 Series and Jetty", [(0, 15), (20, 25)], FakeDF(), 0.01)
    assert out == f"{et.MARKER} and {et.MARKER}"
    assert replaced == 2


def test_drop_removes_span_and_leaves_no_residue():
    """`drop` is the arm testing that in replace mode the removal is the
    mechanism and the marker is dead weight. It must not leave double spaces
    -- those survive into the char_wb vectorizer as real n-grams."""
    out, replaced, _ = et.replace_spans(
        "nmap scan attempt", [(0, 4)], FakeDF(), 0.01, style="drop")
    assert out == "scan attempt"
    assert replaced == 1


def test_sentinel_survives_word_tokenization_intact():
    """The point of `sentinel`: unlike `<ENTITY>`, sklearn's default word
    token pattern must not erode it into a real word."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    out, _, _ = et.replace_spans(
        "nmap scan", [(0, 4)], FakeDF(), 0.01, style="sentinel")
    v = TfidfVectorizer(analyzer="word", ngram_range=(1, 1), min_df=1)
    v.fit([out.lower()])
    assert et.SENTINEL in set(v.get_feature_names_out())


def test_marker_does_NOT_survive_word_tokenization():
    """Records the measured defect motivating the other two styles: the word
    vectorizer strips the angle brackets, so <ENTITY> collides with the
    ordinary word 'entity'. If this ever starts failing, the marker became a
    real reserved token and the style comparison should be revisited."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    out, _, _ = et.replace_spans(
        "nmap scan", [(0, 4)], FakeDF(), 0.01, style="marker")
    v = TfidfVectorizer(analyzer="word", ngram_range=(1, 1), min_df=1)
    v.fit([out.lower()])
    feats = set(v.get_feature_names_out())
    assert "entity" in feats and et.MARKER.lower() not in feats


def test_all_three_styles_key_different_caches():
    """Three arms emitting different text must not share the 49MB embedding
    cache, or arms 2 and 3 silently score arm 1's vectors."""
    seen = {}
    for style in et.REPLACEMENT_STYLES:
        t = et.EntityTagger.__new__(et.EntityTagger)
        t.merge_rule, t.spans_path, t.df_path = "gliner_only", "x", None
        t.replace_rare, t.df_cutoff, t.replacement_style = True, 0.01, style
        seen[style] = t.fingerprint()
    assert len(set(seen.values())) == 3, seen


def test_unknown_style_is_rejected():
    try:
        et.replace_spans("a b", [(0, 1)], FakeDF(), 0.01, style="bogus")
    except ValueError:
        return
    raise AssertionError("bogus style should have raised")


def test_drop_never_returns_an_empty_document():
    """A title that IS one entity is fully covered by its own span, so `drop`
    would erase it. An empty document is an all-zero TF-IDF row: the SVM then
    classifies from the origin and kNN retrieves against a degenerate vector,
    both yielding a confident prediction from no information. Floor it."""
    out, replaced, kept = et.replace_spans(
        "Jetty", [(0, 5)], FakeDF(), 0.01, style="drop")
    assert out == "Jetty"
    assert replaced == 0 and kept == 1


def test_floor_applies_to_every_style():
    for style in et.REPLACEMENT_STYLES:
        out, _, _ = et.replace_spans(
            "Jetty", [(0, 5)], FakeDF(), 0.01, style=style)
        assert out.strip(), f"{style} produced an empty document"


def test_sentinel_is_absent_from_the_corpora():
    """`sentinel` only separates 'placeholder helps' from 'placeholder
    collides' if it collides with nothing. Measured against the real DF table
    when one is built; the literal is asserted collision-free by shape here."""
    assert et.SENTINEL.isalpha() and et.SENTINEL.islower()


def test_reserved_placeholders_are_off_by_default():
    """Every number on this branch assumes the angle-bracket forms. Flipping
    the default would silently re-baseline the whole report."""
    assert et.RESERVED_PLACEHOLDERS is False
    assert et.placeholder_for("<CVE>") == "<CVE>"


def test_reserved_placeholders_substitute_when_enabled():
    et.RESERVED_PLACEHOLDERS = True
    try:
        assert et.placeholder_for("<CVE>") == "qqcveqq"
        assert et.placeholder_for("<VERSION>") == "qqverqq"
    finally:
        et.RESERVED_PLACEHOLDERS = False


def test_placeholder_mode_keys_a_different_cache():
    """The two modes emit different baseline text, so they must not share the
    embedding cache -- this one affects runs with tagging entirely off."""
    before = et.fingerprint()
    et.RESERVED_PLACEHOLDERS = True
    try:
        assert et.fingerprint() != before
    finally:
        et.RESERVED_PLACEHOLDERS = False
    assert et.fingerprint() == before
