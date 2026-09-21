"""Typed markers (effort 17) -- one qq<type>qq sentinel per entity type
instead of one generic <ENTITY>, gated to a spans artifact that stores types.

Same rationale as test_entity_replace.py's docstring: every case here would
otherwise fail silently by producing a plausible-looking (wrong) marker or by
quietly reusing the old generic-marker behaviour, rather than an error.
"""
import gzip
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from attack_mapper import entity_tagger as et  # noqa: E402


# ---------------------------------------------------------------------------
# Pure functions: gazetteer_spans / merge_spans / inject_typed_markers /
# _sentinel_for_type. No artifact needed.
# ---------------------------------------------------------------------------

def test_gazetteer_spans_are_4tuples_with_no_type():
    """Gazetteer spans stay untyped by design (TYPE_MARKERS comment: its
    free-text CSV type has never been measured for accuracy), so the 4th
    element must be the empty string, not missing."""
    single, multi = et.load_gazetteer()
    spans = et.gazetteer_spans("nmap scan", single, multi)
    assert all(len(s) == 4 and s[3] == "" for s in spans)


def test_merge_spans_default_is_unchanged_2tuples():
    """Backward-compat guard: marker_rate.py and cutoff_screen.py call
    merge_spans() without with_types and unpack 2-tuples. This must still
    hold after the typed-markers change."""
    spans = [(0, 4, "gliner", "TOOL"), (5, 9, "gazetteer", "")]
    out = et.merge_spans(spans, "union")
    assert out == [(0, 4), (5, 9)]
    for item in out:
        assert len(item) == 2


def test_merge_spans_with_types_prefers_ner_type_over_gazetteer():
    """Where NER and the gazetteer both fire on the same region, the NER
    type wins -- TYPE_MARKERS comment: the gazetteer's type is unvalidated
    and never surfaced, even when it's the one that agrees."""
    spans = [(0, 4, "gliner", "TOOL"), (0, 4, "gazetteer", "")]
    out = et.merge_spans(spans, "union", with_types=True)
    assert out == [(0, 4, "TOOL")]


def test_merge_spans_with_types_untyped_for_gazetteer_only_hit():
    """A span only the gazetteer found (no overlapping NER span) gets
    UNTYPED_TYPE, not a made-up type."""
    spans = [(10, 15, "gazetteer", "")]
    out = et.merge_spans(spans, "union", with_types=True)
    assert out == [(10, 15, et.UNTYPED_TYPE)]


def test_sentinel_for_type_sanitizes_hyphens_and_case():
    """MITRE-TACTIC must collapse to ONE word-shaped token. Left as
    '<MITRE-TACTIC>', sklearn's \\w\\w+ tokenizer would split it into two
    tokens ('mitre', 'tactic') on the hyphen, silently breaking the
    one-marker-per-span invariant every other placeholder in this module
    keeps (see the TYPE_MARKERS comment)."""
    s = et._sentinel_for_type("MITRE-TACTIC")
    assert s == "qqe_mitretacticqq"
    assert "-" not in s and s == s.lower()


def test_type_markers_cover_the_full_smb_schema():
    assert set(et.SMB_TYPES) <= set(et.TYPE_MARKERS)
    assert et.UNTYPED_TYPE in et.TYPE_MARKERS


def test_inject_typed_markers_uses_per_type_sentinel():
    out = et.inject_typed_markers("Cisco ASA reload", [(0, 5, "ORG")])
    assert out == f"Cisco {et.TYPE_MARKERS['ORG']}  ASA reload"


def test_inject_typed_markers_unknown_type_falls_back_to_untyped():
    """Schema drift (a label the pinned model version didn't have when
    SMB_TYPES was enumerated) must not KeyError -- it falls back visibly to
    the untyped sentinel rather than crashing a validate.py run."""
    out = et.inject_typed_markers("x", [(0, 1, "SOME-NEW-LABEL")])
    assert et.TYPE_MARKERS[et.UNTYPED_TYPE] in out


def test_typed_and_generic_markers_never_collide():
    """The two mechanisms must be textually distinguishable, otherwise a run
    mixing typed and untyped text (e.g. comparing report files by eye) can't
    tell them apart."""
    assert et.MARKER not in et.TYPE_MARKERS.values()
    assert all(m != et.SENTINEL for m in et.TYPE_MARKERS.values())


# ---------------------------------------------------------------------------
# EntityTagger construction: the has_types artifact gate.
# ---------------------------------------------------------------------------

def _write_spans_artifact(path, has_types):
    # Keyed by the FULL text (normalize.entity_key()'s output), not a
    # substring -- see build_spans.py's module docstring.
    spans = ({"x scan": [[0, 1, 0.9, "TOOL"]]} if has_types
            else {"x scan": [[0, 1, 0.9]]})
    blob = {
        "meta": {
            "backend": "securemodernbert", "model": et.SMB_MODEL,
            "threshold": None, "labels": None, "has_types": has_types,
            "built": "test", "n_texts": len(spans), "note": "fixture",
        },
        "spans": spans,
    }
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(blob, fh)


def test_typed_markers_requires_has_types_artifact():
    """An artifact built before effort 17 (or with the wrong backend) has no
    per-span types. Loading it in typed mode must fail loudly -- the
    alternative is every span silently falling back to UNTYPED_TYPE, which
    looks exactly like a real (null) result instead of a misconfigured run.
    """
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "spans.json.gz")
        _write_spans_artifact(path, has_types=False)
        try:
            et.EntityTagger(merge_rule="gliner_only", spans_path=path,
                            ner_backend="securemodernbert", typed_markers=True)
            assert False, "expected SpansArtifactError"
        except et.SpansArtifactError:
            pass


def test_typed_markers_accepts_has_types_artifact():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "spans.json.gz")
        _write_spans_artifact(path, has_types=True)
        tagger = et.EntityTagger(merge_rule="gliner_only", spans_path=path,
                                 ner_backend="securemodernbert", typed_markers=True)
        assert tagger.tag("x scan") == f"x {et.TYPE_MARKERS['TOOL']}  scan"


class _FakeDF:
    """Mirrors test_entity_replace.py's fixture so these cases need no built
    DF artifact. Values are the real measured ones."""

    TABLE = {"sql": 0.1206, "cisco": 0.0, "asa 5500 series": 0.0}

    def is_rare(self, text, cutoff):
        return self.TABLE.get(" ".join(text.lower().split()), 0.0) < cutoff


def test_typed_replace_substitutes_the_type_sentinel():
    """The supervisor-requested arm: replace low-level artefacts, on the NER
    stack actually in use. A replaced span leaves its TYPE behind, not one
    generic marker -- that is the whole difference from effort 15."""
    text = "Cisco ASA 5500 Series overflow"
    spans = [(0, 5, "ORG"), (6, 21, "PRODUCT")]
    out, replaced, kept = et.replace_typed_spans(text, spans, _FakeDF(), 0.01)
    assert replaced == 2 and kept == 0
    assert et.TYPE_MARKERS["ORG"] in out and et.TYPE_MARKERS["PRODUCT"] in out
    assert "Cisco" not in out


def test_typed_replace_honours_the_df_gate():
    """A frequent span carries the technique signal and must survive, exactly
    as in the untyped path -- the gate is the same, only the substitution
    differs."""
    text = "SQL injection attempt"
    out, replaced, kept = et.replace_typed_spans(
        text, [(0, 3, "PRODUCT")], _FakeDF(), 0.01)
    assert replaced == 0 and kept == 1
    assert out == text


def test_typed_replace_keeps_different_types_distinguishable():
    """Why typing should matter in replace mode at all: generic replacement
    collapses two unrelated rules onto the same string, typed replacement
    only collapses same-kind entities."""
    a, _, _ = et.replace_typed_spans("Cisco reload", [(0, 5, "ORG")], _FakeDF(), 0.01)
    b, _, _ = et.replace_typed_spans("Cisco scan", [(0, 5, "PRODUCT")], _FakeDF(), 0.01)
    assert a.split()[0] != b.split()[0]


def test_fingerprint_differs_between_typed_and_untyped():
    """The embedding cache key must change with typed mode, or a typed run
    would silently score a generic-marker run's cached vectors."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "spans.json.gz")
        _write_spans_artifact(path, has_types=True)
        generic = et.EntityTagger(merge_rule="gliner_only", spans_path=path,
                                  ner_backend="securemodernbert")
        typed = et.EntityTagger(merge_rule="gliner_only", spans_path=path,
                                ner_backend="securemodernbert", typed_markers=True)
        assert generic.fingerprint() != typed.fingerprint()
