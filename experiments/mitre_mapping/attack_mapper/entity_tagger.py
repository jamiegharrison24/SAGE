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
SMB_SPANS_PATH = os.path.join(DATA, "entity_spans_smb.json.gz")

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

# Cyber-domain-trained alternative to GLiNER's generic zero-shot pass, per
# `entity_ner/comparison_findings.md`'s addendum: on two independent
# span-level samples (30 and 100 titles) it beat both GLiNER and NuNER Zero
# on precision, rare-entity recall, and noise burden. Fixed 22-label schema
# (token classification), so unlike GLiNER there is no threshold or label-set
# lever -- `NER_THRESHOLD`/`NER_LABELS` above are meaningless for this
# backend. `aggregation_strategy="first"` per `compare_ner.py.run_securebert`'s
# precedent: `"simple"` returns subword fragments because adjacent subwords of
# one word get different labels, which blocks grouping.
SMB_MODEL = "attack-vector/SecureModernBERT-NER"
SMB_AGGREGATION = "first"

# The fixed 22-type schema (`AutoConfig.from_pretrained(SMB_MODEL).id2label`,
# B-/I- prefixes stripped and de-duplicated, `O` excluded) -- enumerated once
# from the model's own config rather than the handful of types that showed up
# in the 30/100-title samples, so the marker map below is complete against
# what the model can actually emit, not what happened to be observed.
SMB_TYPES = (
    "URL", "ORG", "SERVICE", "SECTOR", "FILEPATH", "DOMAIN", "PLATFORM",
    "THREAT-ACTOR", "PRODUCT", "MALWARE", "LOC", "CVE", "TOOL", "IPV4",
    "MITRE-TACTIC", "MD5", "CAMPAIGN", "SHA1", "SHA256", "EMAIL", "IPV6",
    "REGISTRY-KEYS",
)

# Registry of NER backends `EntityTagger(ner_backend=...)` can select.
# `spans_path` is backend-specific so a GLiNER build and a SecureModernBERT
# build never collide or silently mix -- each backend's spans live in their
# own artifact, checked against their own `meta` on load.
NER_BACKENDS = {
    "gliner": {
        "model": NER_MODEL,
        "labels": NER_LABELS,
        "threshold": NER_THRESHOLD,
        "spans_path": SPANS_PATH,
    },
    "securemodernbert": {
        "model": SMB_MODEL,
        "labels": None,       # fixed schema; not a declared-label model
        "threshold": None,    # fixed-schema token classifier; no lever
        "spans_path": SMB_SPANS_PATH,
    },
}
DEFAULT_NER_BACKEND = "securemodernbert"
# Was "gliner" through effort 16. Flipped per explicit project direction
# (GLiNER is no longer in active use; typed NER -- SecureModernBERT's fixed
# schema is what makes typing viable at all, effort 17 -- is the supervisor-
# directed standard going forward, ahead of the corpus expansion effort 14
# identifies as the actual binding constraint). GLiNER's artifact/backend
# still works unchanged for anyone who passes `--ner-backend gliner`
# explicitly (reproducing effort 13's numbers needs exactly that).

MARKER = "<ENTITY>"

# ---------------------------------------------------------------------------
# Typed markers (effort 17): one qq<type>qq sentinel per entity type instead
# of one generic <ENTITY>.
#
# Deliberately NOT a reopening of the 2026-09-11 "generic, not typed"
# decision recorded in `entity_ner/replace_prereg.md` -- that decision was
# measured against GLiNER/the gazetteer, both ~20% wrong on type (`fortios`
# tagged a product, `FortiOS` tagged a company). It was never re-measured
# against SecureModernBERT, whose fixed 22-label schema is the reason it
# clears the pre-registered gate at all (`entity_ner/comparison_findings.md`)
# -- and per that same doc's "Two real, measured weaknesses" section it is
# NOT immune to the same failure (`Cisco` -> PRODUCT in one title, -> ORG two
# rows later; `IBM Tivoli Endpoint` splits into ORG + TOOL). So this is a new,
# separate arm to measure, not a correction of the old one -- gated behind
# `EntityTagger(typed_markers=True)`, off by default, and the untyped path
# below is untouched so effort 13/16's numbers stay reproducible.
#
# Sentinel, not literal <TYPE>: the same collision MARKER/SENTINEL already
# document above applies here, worse. sklearn's default `\w\w+` token pattern
# strips angle brackets, so `<PRODUCT>` would tokenize to the bare word
# `product` -- a real word in rule titles -- and a hyphenated type like
# `<MITRE-TACTIC>` would additionally split into two tokens (`mitre`,
# `tactic`) since `-` isn't a word character, silently breaking the
# one-marker-per-span invariant every other placeholder in this module keeps.
# `qq...qq` sentinels (the existing convention: `SENTINEL`, `RESERVED_MAP`)
# survive tokenization as one word-shaped token that appears nowhere in
# ordinary English or the corpora.
#
# Namespaced `qqe_...qq` (not `qqcveqq` etc.) so this mechanism never collides
# with `RESERVED_MAP`'s sentinels even though both happen to cover CVE --
# they are two unrelated placeholder systems (normalize.py's older literal
# `<CVE>`/`<IP>`/`<HEX>`/`<VERSION>` substitution vs. this module's NER spans)
# and conflating their tokens would make a stale-cache-style bug invisible.


def _sentinel_for_type(etype: str) -> str:
    return "qqe_" + re.sub(r"[^a-z0-9]", "", etype.lower()) + "qq"


TYPE_MARKERS = {t: _sentinel_for_type(t) for t in SMB_TYPES}

# Fallback for a span with no NER type in typed mode: a gazetteer-only hit
# (union/gliner_primary can keep one when NER missed it), or a label the
# pinned model version emits that isn't in SMB_TYPES (schema drift). The
# gazetteer's own free-text type (`"software product"`, `"network
# protocol"`, ... from the CSV) is deliberately not surfaced as a marker --
# it has never been measured for per-type accuracy the way SMB_TYPES has, so
# surfacing it would reintroduce exactly the untrusted-type problem this
# feature exists to avoid for the NER side.
UNTYPED_TYPE = "__untyped__"
TYPE_MARKERS[UNTYPED_TYPE] = "qqe_untypedqq"

# Replace a span only when its corpus document frequency is strictly below
# this. 1% sits an order of magnitude under the frequent tokens the report
# names as must-keep (`SQL` 12.1%, `Injection Attempt` 12.0%, `HTTP` 12.2%)
# and above GLiNER's residual false positives at 0.85 (`URI` 0.62%, `URL`
# 0.18%, `UDN` 0.00%). It is a starting point for the sweep, not a finding.
DEFAULT_DF_CUTOFF = 0.01

# How a replaced span is substituted. Measured as an arm, because the obvious
# choice is not obviously right:
#
#   marker    "nmap scan" -> "<ENTITY> scan"
#   drop      "nmap scan" -> "scan"
#   sentinel  "nmap scan" -> "qqentqq scan"
#
# `marker` is NOT a reserved symbol to the classifier. Its word vectorizer uses
# sklearn's default token pattern, which strips non-word characters, so
# `<ENTITY>` tokenizes to the bare word `entity` -- colliding with real uses of
# the word (corpus DF 0.07%, and `identity` at 0.13% via char_wb `entit`
# n-grams). The same is already true of the older placeholders: `<CVE>` -> cve,
# `<VERSION>` -> version.
#
# The collision is small; the dilution is not. `gliner_only` fires on ~42% of
# rows, so `marker` injects one near-constant word token AND its char n-grams
# into ~42% of documents -- near-zero IDF for itself while shifting every real
# feature's relative weight (the cost `marker_rate.py` documents).
#
# `drop` is the hypothesis that in REPLACE mode the mechanism is the removal
# itself, making the marker dead weight. `sentinel` separates "does a
# placeholder help?" from "does the placeholder collide?" -- it survives word
# tokenization as one distinct token that appears nowhere in the corpora.
REPLACEMENT_STYLES = ("marker", "drop", "sentinel")
DEFAULT_REPLACEMENT_STYLE = "marker"

# Deliberately lowercase and alphabetic: `canonicalize()` lowercases after
# tagging, and anything non-alphanumeric would be stripped by the word
# tokenizer exactly as the angle brackets are.
SENTINEL = "qqentqq"

# ---------------------------------------------------------------------------
# Reserved placeholders for the OLDER entity classes (effort 15 follow-up).
#
# `normalize.placeholder_entities` substitutes `<CVE>`, `<IP>`, `<HEX>` and
# `<VERSION>`, and none of the four is a distinct token to the classifier: its
# word vectorizer uses sklearn's default `\w\w+`, which strips the angle
# brackets, so `<cve>` is read as the ordinary word `cve`. The collapsing these
# placeholders exist to do still works -- every CVE id lands on one shared
# token -- but that token is not reserved, so it merges with literal uses of
# the word.
#
# Measured before changing anything: `<CVE>` fires on 5.48% of corpus rows
# (1,744), `<VERSION>` 0.32%, `<HEX>` 0.20%, `<IP>` 0.01%; the literal words
# collide at `cve` 0.041% and `version` 0.047% of rows. So the defect is real
# but small, which is why this is a measured arm rather than an assumed fix.
#
# Flipping this changes BASELINE text, so it invalidates every number on the
# branch. It is therefore a module global defaulting to the existing
# behaviour, folded into `fingerprint()` below so the embedding cache cannot
# be shared across the two.
RESERVED_PLACEHOLDERS = False

# Alphabetic and lowercase for the same reason as SENTINEL: `canonicalize()`
# lowercases after substitution, and anything non-alphanumeric would be
# stripped by the word tokenizer exactly as the angle brackets are.
RESERVED_MAP = {
    "<CVE>": "qqcveqq",
    "<IP>": "qqipqq",
    "<HEX>": "qqhexqq",
    "<VERSION>": "qqverqq",
}


def placeholder_for(tag: str) -> str:
    """The substitution for one placeholder class, honouring the global."""
    return RESERVED_MAP[tag] if RESERVED_PLACEHOLDERS else tag


# Bump on ANY change to normalisation behaviour -- this string is hashed into
# `knn_resolver._corpus_fingerprint()`, and a stale 49MB embedding cache
# silently reused across a normalisation change produces plausible-looking
# numbers that mean nothing. See plan §4.
NORMALIZER_VERSION = "3-entity-replace"

MERGE_RULES = ("union", "intersection", "gliner_only", "gazetteer_only",
               "gliner_primary")
DEFAULT_MERGE_RULE = "union"

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")

Span = Tuple[int, int, str, str]  # (start, end, source, etype)
# `etype` is "" for the gazetteer (never typed -- see UNTYPED_TYPE above) and
# for spans read from a pre-typed-markers artifact that has no 4th element.
# Every producer below fills it in as best it can; only `merge_spans(...,
# with_types=True)` and its callers actually read it, so an empty string is a
# silent no-op everywhere else, not a bug.


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
                found.append((toks[i][0], toks[i + size - 1][1], "gazetteer", ""))

    for start, end, tok in toks:
        if tok in single or tok.rstrip(".-_") in single:
            found.append((start, end, "gazetteer", ""))
    return found


# ---------------------------------------------------------------------------
# Span merging + marker injection
# ---------------------------------------------------------------------------

def _overlaps(a: Span, b: Span) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def merge_spans(spans: Sequence[Span], rule: str = DEFAULT_MERGE_RULE,
                with_types: bool = False):
    """Apply a merge rule to raw (start, end, source, etype) spans.

    The artifact stores raw spans *with their source*, so every rule can be
    swept over one cached NER pass rather than re-running it per variant.

    Note that `union` and `gliner_primary` are near-duplicates in practice.
    Both keep every non-overlapping span; they differ only in the *extent* of a
    partially-overlapping pair (union fuses to the outer hull, gliner_primary
    keeps GLiNER's boundaries). Since markers are appended rather than
    substituted, extent only moves where the marker lands, not how many appear
    -- so the sweep has four meaningful arms, not five.

    Returns `List[Tuple[int, int]]` by default -- unchanged from before typed
    markers existed, so every existing caller (`marker_rate.py`,
    `cutoff_screen.py`, the tests) keeps working untouched. `with_types=True`
    returns `List[Tuple[int, int, str]]` instead, one etype per collapsed
    range, for `inject_typed_markers`.
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

    if not with_types:
        return out

    # Assign each collapsed range a type. Prefer an NER-sourced type (`gl`)
    # over the gazetteer's when both land in the range: NER's type is the
    # thing this feature measures (SMB_TYPES, per comparison_findings.md);
    # the gazetteer's is unvalidated free text from the CSV and is never
    # surfaced (UNTYPED_TYPE) even when it is the only source that fired.
    typed: List[Tuple[int, int, str]] = []
    for start, end in out:
        ner_hit = next((s for s in gl if s[0] < end and start < s[1]), None)
        etype = (ner_hit[3] if ner_hit and ner_hit[3] else None) or UNTYPED_TYPE
        typed.append((start, end, etype))
    return typed


def inject_markers(text: str, spans: Sequence[Tuple[int, int]],
                   marker: str = MARKER) -> str:
    """Append `marker` after each span. Right-to-left so earlier offsets stay
    valid as the string grows."""
    out = text
    for start, end in sorted(spans, reverse=True):
        out = out[:end] + " " + marker + " " + out[end:]
    return out


def inject_typed_markers(text: str, typed_spans: Sequence[Tuple[int, int, str]]) -> str:
    """Like `inject_markers`, but appends `TYPE_MARKERS[etype]` per span
    instead of one constant marker. Takes `merge_spans(..., with_types=True)`
    output specifically -- (start, end) pairs from the untyped path have
    nothing to look up and will fail to unpack.
    """
    out = text
    for start, end, etype in sorted(typed_spans, reverse=True):
        marker = TYPE_MARKERS.get(etype, TYPE_MARKERS[UNTYPED_TYPE])
        out = out[:end] + " " + marker + " " + out[end:]
    return out


def replace_spans(text: str, spans: Sequence[Tuple[int, int]],
                  df_table, cutoff: float,
                  marker: str = MARKER,
                  style: str = DEFAULT_REPLACEMENT_STYLE) -> Tuple[str, int, int]:
    """Substitute `marker` for each span whose surface DF is below `cutoff`.

    This is the *replace* arm of REPORT.md §8 item 7, and the only variant that
    implements effort 13's original hypothesis. `inject_markers` (augment) is
    left exactly as it was: effort 13's 19.4%/21.3% numbers have to stay
    reproducible for this comparison to mean anything, so this is a second path
    rather than a mutation of the first.

    Why replace rather than append. Augment leaves the rare token in place, so
    `nmap <ENTITY> scan` and `masscan <ENTITY> sweep` still differ in every
    token that made them differ before -- the marker adds a constant and
    changes no distance. Replacement is what actually makes two rules alike:
    `<ENTITY> scan` vs `<ENTITY> sweep`.

    Why gated on DF. Replacement destroys the surface token. For `ASA 5500
    Series` (DF 0.00%) that is the point; for `SQL` (DF 12.1%) it would delete
    the token carrying the technique signal. The gate is measured corpus
    document frequency, never a hand-written list -- see `df_table.py`.

    Returns (text, n_replaced, n_kept) so the caller can report how often the
    gate actually fired. A run where `n_replaced` is ~0 is a no-op arm, and a
    run where `n_kept` is ~0 replaced everything; both are failures that look
    like results if they are not counted.
    """
    if style not in REPLACEMENT_STYLES:
        raise ValueError(f"unknown replacement style {style!r}; "
                         f"expected one of {REPLACEMENT_STYLES}")
    sub = {"marker": marker, "drop": "", "sentinel": SENTINEL}[style]

    replaced = kept = 0
    out = text
    for start, end in sorted(spans, reverse=True):
        if df_table.is_rare(text[start:end], cutoff):
            out = out[:start] + sub + out[end:]
            replaced += 1
        else:
            kept += 1
    # `drop` leaves double spaces where spans were excised. canonicalize()
    # collapses whitespace as its last step, but replace_spans is also called
    # directly (tests, cutoff_screen), so normalise here rather than depending
    # on a caller that may not exist.
    out = " ".join(out.split())

    # Floor: never hand back an empty document. A title that IS one entity
    # ("Mimikatz", "Sipvicious") is fully covered by its own span, and under
    # `drop` that erases the text completely. An empty document is not an
    # error anywhere downstream -- it is an all-zero TF-IDF row, so the SVM
    # classifies from the origin and kNN retrieves against a degenerate
    # vector. Those rows still emit a confident-looking prediction derived
    # from no information at all, which is worse than not replacing.
    if not out:
        return text, 0, len(spans)

    return out, replaced, kept


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
                 spans_path: Optional[str] = None,
                 gazetteer_path: str = GAZETTEER_PATH,
                 allow_live_ner: bool = False,
                 replace_rare: bool = False,
                 df_cutoff: float = DEFAULT_DF_CUTOFF,
                 replacement_style: str = DEFAULT_REPLACEMENT_STYLE,
                 df_path: Optional[str] = None,
                 ner_backend: str = DEFAULT_NER_BACKEND,
                 typed_markers: bool = False):
        if merge_rule not in MERGE_RULES:
            raise ValueError(f"unknown merge rule {merge_rule!r}")
        self.merge_rule = merge_rule
        if replacement_style not in REPLACEMENT_STYLES:
            raise ValueError(f"unknown replacement style {replacement_style!r}")
        if ner_backend not in NER_BACKENDS:
            raise ValueError(f"unknown ner_backend {ner_backend!r}; "
                             f"expected one of {list(NER_BACKENDS)}")
        if typed_markers and replace_rare:
            # Not measured together deliberately (advisor note, effort 17):
            # replace-mode was already measured decisively negative on its
            # own (replace_prereg.md, -5.0 to -5.8 macro), so stacking a
            # second changed variable on top gives an unreadable result.
            # `replace_spans` also only understands (start, end) pairs, not
            # the (start, end, etype) triples typed mode produces.
            raise ValueError("typed_markers + replace_rare is not supported; "
                             "these are separate, un-stacked experiment arms")
        self.typed = typed_markers
        self.replace_rare = replace_rare
        self.df_cutoff = float(df_cutoff)
        self.replacement_style = replacement_style
        self.df_table = None
        self.replaced = 0
        self.kept_frequent = 0
        if replace_rare:
            # Imported lazily: the augment path and every existing caller must
            # keep working on a checkout with no DF artifact built.
            from .entity_ner.df_table import DFTable, DF_PATH
            self.df_path = df_path or DF_PATH
            self.df_table = DFTable(self.df_path)
        else:
            self.df_path = None

        # `spans_path=` explicitly passed always wins (existing callers, tests
        # pointing at a fixture path); otherwise the backend picks its own
        # artifact, so GLiNER and SecureModernBERT spans never collide.
        self.ner_backend = ner_backend
        backend_cfg = NER_BACKENDS[ner_backend]
        self._ner_model = backend_cfg["model"]
        self._ner_labels = backend_cfg["labels"]
        self._ner_threshold = backend_cfg["threshold"]
        self.spans_path = spans_path or backend_cfg["spans_path"]

        self.allow_live_ner = allow_live_ner
        self._live_model = None
        self.misses = 0
        self.tagged = 0
        self.calls = 0

        need_ner = merge_rule != "gazetteer_only"
        self.ner_spans: Dict[str, List[List]] = {}
        self.artifact_meta: Dict[str, object] = {}

        if need_ner:
            if not os.path.exists(self.spans_path):
                raise SpansArtifactError(
                    f"entity spans artifact not found at {self.spans_path}.\n"
                    f"Run:  python -m attack_mapper.entity_ner.build_spans "
                    f"--backend {ner_backend}\n"
                    f"(~30-55 min for the full corpus; it is cached afterwards).\n"
                    f"Merge rule 'gazetteer_only' needs no artifact."
                )
            with gzip.open(self.spans_path, "rt", encoding="utf-8") as fh:
                blob = json.load(fh)
            self.artifact_meta = blob.get("meta", {})
            self._check_artifact_meta()
            if self.typed and not self.artifact_meta.get("has_types"):
                # Deliberately fatal, same reasoning as SpansArtifactError's
                # class docstring: an untyped artifact read in typed mode
                # would silently fall back to UNTYPED_TYPE on every span (no
                # 4th element to read), which looks exactly like "every
                # marker is qqe_untypedqq" -- i.e. the old generic-marker
                # result under a different name -- rather than an error.
                raise SpansArtifactError(
                    f"{self.spans_path} was built without per-span types "
                    f"(has_types={self.artifact_meta.get('has_types')!r}); "
                    f"typed_markers=True needs an artifact rebuilt with a "
                    f"backend that stores them. Rebuild:  python -m "
                    f"attack_mapper.entity_ner.build_spans --backend "
                    f"{ner_backend}"
                )
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
        """A build made with a different backend, model, threshold or label
        set produces spans inconsistent with anything computed live. Fail
        loudly."""
        m = self.artifact_meta
        mismatches = []
        if m.get("backend", "gliner") != self.ner_backend:
            mismatches.append(
                f"backend {m.get('backend', 'gliner')!r} != {self.ner_backend!r}")
        if m.get("model") != self._ner_model:
            mismatches.append(f"model {m.get('model')!r} != {self._ner_model!r}")
        if self._ner_threshold is not None and m.get("threshold") != self._ner_threshold:
            mismatches.append(
                f"threshold {m.get('threshold')} != {self._ner_threshold}")
        if self._ner_labels is not None and tuple(m.get("labels") or ()) != self._ner_labels:
            mismatches.append("label set differs")
        if mismatches:
            raise SpansArtifactError(
                f"{self.spans_path} was built with a different configuration: "
                + "; ".join(mismatches)
                + ".\nRebuild it (entity_ner/build_spans.py --backend "
                f"{self.ner_backend}) or revert the constants in entity_tagger.py."
            )

    def assert_complete(self, expected: int, tolerance: float = 0.02) -> None:
        """Fail unless the artifact covers ~every text the run will query.

        `_check_artifact_meta` validates model, threshold and labels but NOT
        size, so an artifact left behind by `build_spans.py --limit 40` passes
        it cleanly. With `allow_live_ner=False` every cache miss then returns
        no spans, so the run produces almost no tags and scores like the
        off-baseline -- a partial build is indistinguishable from "the feature
        did not help", which is the one conclusion this experiment exists to
        draw. Callers running a measured arm must invoke this; it is not
        automatic because a deliberate `--limit` smoke test is legitimate.
        """
        have = len(self.ner_spans)
        if have < expected * (1 - tolerance):
            raise SpansArtifactError(
                f"{self.spans_path} covers {have} texts but this run queries "
                f"~{expected}. It looks like a partial (--limit) build. "
                f"A partial artifact yields no spans on every miss and scores "
                f"like the baseline -- rerun "
                f"`python -m attack_mapper.entity_ner.build_spans` in full."
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
            # 4th element (label) only present for a backend build_spans.py
            # stores types for (securemodernbert). Absent -> "", same as the
            # gazetteer's untyped spans -- merge_spans(with_types=True) maps
            # that to UNTYPED_TYPE like any other type-less hit.
            spans += [(s[0], s[1], "gliner", s[3] if len(s) > 3 else "")
                     for s in cached]
        return spans

    def _live_ner(self, text: str) -> List[List]:
        """Cache miss. Only reachable for text the build script never saw."""
        if not self.allow_live_ner:
            return []
        if self.ner_backend == "securemodernbert":
            if self._live_model is None:
                from transformers import pipeline  # heavy import, deferred
                self._live_model = pipeline(
                    "token-classification", model=self._ner_model,
                    aggregation_strategy=SMB_AGGREGATION)
            ents = self._live_model(text)
            spans = [[int(e["start"]), int(e["end"]), float(e["score"]),
                     e["entity_group"]] for e in ents]
        else:
            if self._live_model is None:
                from gliner import GLiNER  # heavy import, deferred
                self._live_model = GLiNER.from_pretrained(self._ner_model)
            ents = self._live_model.predict_entities(
                text, list(self._ner_labels), threshold=self._ner_threshold)
            spans = [[e["start"], e["end"], e["score"]] for e in ents]
        self.ner_spans[text] = spans  # memoise within the process
        return spans

    def tag(self, text: str) -> str:
        self.calls += 1
        if self.typed:
            # Separate branch, not a fallthrough: typed spans are 3-tuples
            # (start, end, etype), and replace_rare is rejected for this mode
            # in __init__, so there is nothing past this to share with the
            # untyped path below.
            typed_spans = merge_spans(self._spans_for(text), self.merge_rule,
                                      with_types=True)
            if not typed_spans:
                return text
            self.tagged += 1
            return inject_typed_markers(text, typed_spans)

        merged = merge_spans(self._spans_for(text), self.merge_rule)
        if not merged:
            return text
        if not self.replace_rare:
            self.tagged += 1
            return inject_markers(text, merged)

        out, replaced, kept = replace_spans(
            text, merged, self.df_table, self.df_cutoff,
            style=self.replacement_style)
        self.replaced += replaced
        self.kept_frequent += kept
        # A row whose every span cleared the DF gate is untouched text, so it
        # is not "tagged" -- counting it would overstate coverage in exactly
        # the arm whose whole question is how often the gate fires.
        if replaced:
            self.tagged += 1
        return out

    def fingerprint(self) -> str:
        """Identity of everything that affects the emitted text.

        Hashed into the kNN embedding cache key. Derived from the artifact's
        own bytes rather than a hand-maintained constant -- a version number
        someone forgets to bump is the same silent-stale-cache failure, just
        slower.
        """
        h = hashlib.sha256()
        h.update(f"{self.merge_rule}|{MARKER}".encode())

        # Typed-marker identity. `TYPE_MARKERS` is a module constant today,
        # but hashing it rather than just a "typed" flag means a future edit
        # to the sentinel map invalidates old caches automatically instead of
        # silently reusing embeddings keyed under the old text -- the same
        # "derived from bytes, not a version someone forgets to bump" reason
        # this whole method is structured this way.
        h.update(b"|typed:1:" if self.typed else b"|typed:0")
        if self.typed:
            h.update("|".join(f"{k}={v}" for k, v in sorted(TYPE_MARKERS.items())).encode())

        # Replace-mode identity. Two runs at different DF cutoffs emit
        # DIFFERENT text from the same spans, so without this they would key
        # the same 49MB embedding cache and the second run would silently
        # score the first run's vectors -- plausible numbers that mean nothing
        # (plan §4). The augment path hashes the literal "augment" so its
        # existing cache keys are unchanged by this feature landing.
        if self.replace_rare:
            h.update(f"|replace:{self.df_cutoff!r}:{self.replacement_style}".encode())
        else:
            h.update(b"|augment")

        paths = [GAZETTEER_PATH]
        if self.merge_rule != "gazetteer_only":
            # Only hash NER identity when NER actually contributes. Otherwise a
            # `gazetteer_only` run before the spans artifact exists and one
            # after it would key different embedding caches despite producing
            # byte-identical text, forcing a needless 45s re-embed and inviting
            # the difference to be read as noise.
            h.update(f"{self.ner_backend}|{self._ner_model}|{self._ner_threshold}".encode())
            h.update("|".join(self._ner_labels or ()).encode())
            paths.append(self.spans_path)

        if self.replace_rare and self.df_path:
            # A rebuilt DF table changes which spans clear the gate, so it is
            # part of the emitted text's identity just as the spans are.
            paths.append(self.df_path)

        for path in paths:
            if os.path.exists(path):
                st = os.stat(path)
                h.update(f"{path}:{st.st_size}:{st.st_mtime_ns}".encode())
        return h.hexdigest()[:16]

    def stats(self) -> str:
        pct = (self.tagged / self.calls) if self.calls else 0.0
        mode = (f"{self.merge_rule}/replace<{self.df_cutoff:.2%}"
                f"/{self.replacement_style}"
                if self.replace_rare else self.merge_rule)
        if self.typed:
            mode += "/typed"
        base = (f"entity tagger [{mode}]: tagged {self.tagged}/"
                f"{self.calls} texts ({pct:.1%}), {self.misses} NER cache misses")
        if not self.replace_rare:
            return base
        total = self.replaced + self.kept_frequent
        share = (self.replaced / total) if total else 0.0
        return (f"{base}; replaced {self.replaced} spans, kept "
                f"{self.kept_frequent} frequent ({share:.1%} replaced)")


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
    ph = "reserved" if RESERVED_PLACEHOLDERS else "angle"
    if _ACTIVE is None:
        return f"{NORMALIZER_VERSION}|off|ph:{ph}"
    return f"{NORMALIZER_VERSION}|{_ACTIVE.fingerprint()}|ph:{ph}"
