"""
Entity-aware augmentation for `normalize.canonicalize()` -- plan §5 Step 2.

Two entity sources run over the same title and their spans are merged:

  * **gazetteer** (Step 1) -- 94,786 entries from MISP galaxy + IANA + cpedict.
    72.5% row coverage at 53% per-match precision (`entity_dicts/findings.md`).
  * **GLiNER v2.1** zero-shot NER (Step 2) -- fires on 77% of titles, 73%
    per-entity precision at threshold 0.85 (`entity_ner/findings.md`).

Each merged span gets a generic ``<ENTITY>`` marker appended after it, matching
the existing ``<CVE>``/``<IP>`` placeholder convention already in
`normalize.py`. Two deliberate choices, both settled in the plan:

  * **Augment, not replace** (§3.1). ``nmap`` becomes ``nmap <ENTITY>``, never
    bare ``<ENTITY>``. A wrong tag then costs one spurious token rather than
    destroying the word that carried the signal.
  * **Generic, not typed** (user decision, 2026-09-11). Both sources mistype
    products often enough to matter -- the gazetteer calls ``fortios`` a
    product, GLiNER calls ``FortiOS`` a company, and roughly 1 entity in 5
    carries the wrong type. A generic marker makes every such disagreement
    a non-event, and a type that is wrong 20% of the time is worse than no
    type at all.

**Off by default.** `Settings.use_entity_tagging` is False, so importing this
package changes nothing until a caller explicitly enables it -- the same
convention as `NullLLMClient` and the kNN layer.

Why the spans come from a precomputed artifact: a GLiNER pass over the 31,825
corpus rows runs at ~9.9 rows/s, i.e. ~54 minutes. `canonicalize()` is called
once per corpus row on *every* resolver construction, so calling the model
inline would turn a 10-minute experiment cycle into a 70-minute one. The pass
is paid once by `entity_ner/build_spans.py` and cached to disk; this module
only reads it.
"""
import csv
import gzip
import hashlib
import json
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
GAZETTEER_PATH = os.path.join(DATA, "entity_gazetteer.csv")
SPANS_PATH = os.path.join(DATA, "entity_spans.json.gz")

# ---------------------------------------------------------------------------
# Pinned inference configuration.
#
# `build_spans.py` and this module BOTH import these, and the values are
# recorded inside the artifact so a drifted build is detectable rather than
# silent. A live (cache-miss) GLiNER call using a different threshold or label
# set than the batch that built the artifact would produce spans that are
# inconsistent with the cached ones, with no visible error.
# ---------------------------------------------------------------------------

# apache-2.0 only. `gliner_base` and every v0/v1 checkpoint are cc-by-nc-4.0
# (non-commercial) -- see plan §5 "Licence trap". Pinned deliberately.
NER_MODEL = "urchade/gliner_medium-v2.1"

NER_LABELS = (
    "hacking tool",
    "software product",
    "network protocol",
    "malware family",
    "company",
)

# 0.85, not GLiNER's 0.5 default. The trial measured 73% per-entity precision
# here against 53% at 0.5 -- see `entity_ner/findings.md`. Recall drops, but
# the gazetteer covers the gap, which is the point of running both.
NER_THRESHOLD = 0.85

MARKER = "<ENTITY>"

# Bump on ANY change to normalisation behaviour -- this string is hashed into
# `knn_resolver._corpus_fingerprint()`, and a stale 49MB embedding cache
# silently reused across a normalisation change produces plausible-looking
# numbers that mean nothing. See plan §4.
NORMALIZER_VERSION = "2-entity"

MERGE_RULES = ("union", "intersection", "gliner_only", "gazetteer_only",
               "gliner_primary")
DEFAULT_MERGE_RULE = "union"

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")

Span = Tuple[int, int, str]  # (start, end, source)


class SpansArtifactError(RuntimeError):
    """Raised when the precomputed spans artifact is missing or mismatched.

    Deliberately fatal rather than a warning: a silently degraded run that
    produces no tags looks exactly like a baseline run, which is the failure
    `validate.py:check_required_data()` exists to prevent.
    """


# ---------------------------------------------------------------------------
# Gazetteer matching (Step 1), returning char offsets so spans from both
# sources live in the same coordinate space and can be merged.
# ---------------------------------------------------------------------------

def load_gazetteer(path: str = GAZETTEER_PATH) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Returns (single_token_index, multiword_index), each name -> entity type.

    CPE spells multi-word products with underscores (`bb_flashback`), which no
    signature title contains, so those are indexed by their spaced form.
    """
    single: Dict[str, str] = {}
    multi: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name, etype = row["name"], row["type"]
            spaced = name.replace("_", " ").replace("-", " ").strip()
            if " " in spaced:
                multi[spaced] = etype
            else:
                single[name] = etype
    return single, multi


def gazetteer_spans(text: str, single: Dict[str, str], multi: Dict[str, str],
                    max_ngram: int = 4) -> List[Span]:
    """Char-offset spans for gazetteer hits in `text`.

    N-grams are generated from the *title* and looked up in the multi-word
    index, never the reverse -- testing ~30k multi-word entries against each
    title is 12M regex searches over the eval set and does not finish
    (`entity_dicts/measure_coverage.py` carries the same note).
    """
    low = text.lower()
    toks = [(m.start(), m.end(), m.group()) for m in _TOKEN_RE.finditer(low)]
    found: List[Span] = []

    for size in range(max_ngram, 1, -1):
        for i in range(len(toks) - size + 1):
            phrase = " ".join(t[2] for t in toks[i:i + size])
            if phrase in multi:
                found.append((toks[i][0], toks[i + size - 1][1], "gazetteer"))

    for start, end, tok in toks:
        if tok in single or tok.rstrip(".-_") in single:
            found.append((start, end, "gazetteer"))
    return found


# ---------------------------------------------------------------------------
# Span merging + marker injection
# ---------------------------------------------------------------------------

def _overlaps(a: Span, b: Span) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def merge_spans(spans: Sequence[Span], rule: str = DEFAULT_MERGE_RULE) -> List[Tuple[int, int]]:
    """Apply a merge rule to raw (start, end, source) spans.

    The artifact stores raw spans *with their source*, so every rule can be
    swept over one cached NER pass rather than re-running it per variant.

    Note that `union` and `gliner_primary` are near-duplicates in practice.
    Both keep every non-overlapping span; they differ only in the *extent* of a
    partially-overlapping pair (union fuses to the outer hull, gliner_primary
    keeps GLiNER's boundaries). Since markers are appended rather than
    substituted, extent only moves where the marker lands, not how many appear
    -- so the sweep has four meaningful arms, not five.
    """
    if rule not in MERGE_RULES:
        raise ValueError(f"unknown merge rule {rule!r}; expected one of {MERGE_RULES}")

    gl = [s for s in spans if s[2] == "gliner"]
    gz = [s for s in spans if s[2] == "gazetteer"]

    if rule == "gliner_only":
        kept = gl
    elif rule == "gazetteer_only":
        kept = gz
    elif rule == "union":
        kept = list(spans)
    elif rule == "intersection":
        # Only spans both sources agree on -- highest precision, lowest recall.
        kept = [a for a in gl if any(_overlaps(a, b) for b in gz)]
    else:  # gliner_primary -- GLiNER's spans, plus gazetteer hits it missed
        kept = gl + [b for b in gz if not any(_overlaps(a, b) for a in gl)]

    # Collapse overlaps so a region that both sources hit gets ONE marker, not
    # two. Without this, union double-tags every agreed entity and the marker
    # count stops meaning "entities found".
    out: List[Tuple[int, int]] = []
    for start, end in sorted((s[0], s[1]) for s in kept):
        if out and start < out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def inject_markers(text: str, spans: Sequence[Tuple[int, int]],
                   marker: str = MARKER) -> str:
    """Append `marker` after each span. Right-to-left so earlier offsets stay
    valid as the string grows."""
    out = text
    for start, end in sorted(spans, reverse=True):
        out = out[:end] + " " + marker + " " + out[end:]
    return out


# ---------------------------------------------------------------------------
# The tagger
# ---------------------------------------------------------------------------

class EntityTagger:
    """Reads precomputed spans, merges them, injects markers.

    `tag()` is pure string work on a dict lookup -- no model is loaded and no
    inference runs -- so it is safe on the hot path where `canonicalize()` is
    called once per corpus row.
    """

    def __init__(self, merge_rule: str = DEFAULT_MERGE_RULE,
                 spans_path: str = SPANS_PATH,
                 gazetteer_path: str = GAZETTEER_PATH,
                 allow_live_ner: bool = False):
        if merge_rule not in MERGE_RULES:
            raise ValueError(f"unknown merge rule {merge_rule!r}")
        self.merge_rule = merge_rule
        self.spans_path = spans_path
        self.allow_live_ner = allow_live_ner
        self._live_model = None
        self.misses = 0
        self.tagged = 0
        self.calls = 0

        need_gliner = merge_rule != "gazetteer_only"
        self.ner_spans: Dict[str, List[List]] = {}
        self.artifact_meta: Dict[str, object] = {}

        if need_gliner:
            if not os.path.exists(spans_path):
                raise SpansArtifactError(
                    f"entity spans artifact not found at {spans_path}.\n"
                    f"Run:  python -m attack_mapper.entity_ner.build_spans\n"
                    f"(~54 min for the full corpus; it is cached afterwards).\n"
                    f"Merge rule 'gazetteer_only' needs no artifact."
                )
            with gzip.open(spans_path, "rt", encoding="utf-8") as fh:
                blob = json.load(fh)
            self.artifact_meta = blob.get("meta", {})
            self._check_artifact_meta()
            self.ner_spans = blob["spans"]

        self.single, self.multi = ({}, {})
        if merge_rule != "gliner_only":
            if not os.path.exists(gazetteer_path):
                raise SpansArtifactError(
                    f"gazetteer not found at {gazetteer_path} -- run "
                    f"entity_dicts/build_dicts.py"
                )
            self.single, self.multi = load_gazetteer(gazetteer_path)

    def _check_artifact_meta(self) -> None:
        """A build made with a different model, threshold or label set produces
        spans inconsistent with anything computed live. Fail loudly."""
        m = self.artifact_meta
        mismatches = []
        if m.get("model") != NER_MODEL:
            mismatches.append(f"model {m.get('model')!r} != {NER_MODEL!r}")
        if m.get("threshold") != NER_THRESHOLD:
            mismatches.append(f"threshold {m.get('threshold')} != {NER_THRESHOLD}")
        if tuple(m.get("labels") or ()) != NER_LABELS:
            mismatches.append("label set differs")
        if mismatches:
            raise SpansArtifactError(
                f"{self.spans_path} was built with a different configuration: "
                + "; ".join(mismatches)
                + ".\nRebuild it (entity_ner/build_spans.py) or revert the "
                  "constants in entity_tagger.py."
            )

    def _spans_for(self, text: str) -> List[Span]:
        spans: List[Span] = []
        if self.merge_rule != "gliner_only":
            spans += gazetteer_spans(text, self.single, self.multi)
        if self.merge_rule != "gazetteer_only":
            cached = self.ner_spans.get(text)
            if cached is None:
                self.misses += 1
                cached = self._live_ner(text)
            spans += [(s[0], s[1], "gliner") for s in cached]
        return spans

    def _live_ner(self, text: str) -> List[List]:
        """Cache miss. Only reachable for text the build script never saw."""
        if not self.allow_live_ner:
            return []
        if self._live_model is None:
            from gliner import GLiNER  # heavy import, deferred
            self._live_model = GLiNER.from_pretrained(NER_MODEL)
        ents = self._live_model.predict_entities(
            text, list(NER_LABELS), threshold=NER_THRESHOLD)
        spans = [[e["start"], e["end"], e["score"]] for e in ents]
        self.ner_spans[text] = spans  # memoise within the process
        return spans

    def tag(self, text: str) -> str:
        self.calls += 1
        merged = merge_spans(self._spans_for(text), self.merge_rule)
        if not merged:
            return text
        self.tagged += 1
        return inject_markers(text, merged)

    def fingerprint(self) -> str:
        """Identity of everything that affects the emitted text.

        Hashed into the kNN embedding cache key. Derived from the artifact's
        own bytes rather than a hand-maintained constant -- a version number
        someone forgets to bump is the same silent-stale-cache failure, just
        slower.
        """
        h = hashlib.sha256()
        h.update(f"{self.merge_rule}|{MARKER}".encode())

        paths = [GAZETTEER_PATH]
        if self.merge_rule != "gazetteer_only":
            # Only hash NER identity when NER actually contributes. Otherwise a
            # `gazetteer_only` run before the spans artifact exists and one
            # after it would key different embedding caches despite producing
            # byte-identical text, forcing a needless 45s re-embed and inviting
            # the difference to be read as noise.
            h.update(f"{NER_MODEL}|{NER_THRESHOLD}".encode())
            h.update("|".join(NER_LABELS).encode())
            paths.append(self.spans_path)

        for path in paths:
            if os.path.exists(path):
                st = os.stat(path)
                h.update(f"{path}:{st.st_size}:{st.st_mtime_ns}".encode())
        return h.hexdigest()[:16]

    def stats(self) -> str:
        pct = (self.tagged / self.calls) if self.calls else 0.0
        return (f"entity tagger [{self.merge_rule}]: tagged {self.tagged}/"
                f"{self.calls} texts ({pct:.1%}), {self.misses} NER cache misses")


# ---------------------------------------------------------------------------
# Process-global activation.
#
# `canonicalize()` has four call sites across two resolvers (corpus load and
# query, in each), and the entity step has to apply identically at all four or
# train/inference symmetry breaks -- the exact bug this branch already hit once.
# A module-global consulted inside `canonicalize()` makes that structural
# rather than something four call sites have to remember.
# ---------------------------------------------------------------------------

_ACTIVE: Optional[EntityTagger] = None


def enable(merge_rule: str = DEFAULT_MERGE_RULE, **kwargs) -> EntityTagger:
    global _ACTIVE
    _ACTIVE = EntityTagger(merge_rule=merge_rule, **kwargs)
    return _ACTIVE


def disable() -> None:
    global _ACTIVE
    _ACTIVE = None


def active() -> Optional[EntityTagger]:
    return _ACTIVE


def fingerprint() -> str:
    """Normalisation identity for cache keys. Includes the disabled case, so
    toggling the feature off also invalidates the embedding cache."""
    if _ACTIVE is None:
        return f"{NORMALIZER_VERSION}|off"
    return f"{NORMALIZER_VERSION}|{_ACTIVE.fingerprint()}"
