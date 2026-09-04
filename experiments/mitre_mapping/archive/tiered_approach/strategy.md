# Tiered ATT&CK mapping strategy

Pasted reference strategy for mapping Suricata/IDS signatures to MITRE ATT&CK
techniques, evaluated against the existing (bad) results in
`experiments/mitre_mapping/results.md` and `SMET_STATUS.md`.

## Tier 0: harvest the labels that already exist

Most rulesets already carry ATT&CK mappings and people skip straight past them:

- Suricata/Snort ET rules: `metadata:` field often contains `mitre_technique_id T1071`, `mitre_tactic_id TA0011`
- Sigma rules: `tags: [attack.command_and_control, attack.t1071.001]`
- Elastic detection-rules repo: `threat:` block with full technique objects
- Splunk ESCU (security_content repo): `mitre_attack_id` per detection
- Most EDR vendors publish a mapping CSV for their own alert taxonomy

Parse these first. For a lot of environments this alone covers 40–70% of your
signature vocabulary at essentially 100% precision.

## Tier 1: entity extraction → ATT&CK object lookup

Pull the enterprise STIX bundle (`mitre/cti` or `mitre-attack/attack-stix-data`).
It contains not just techniques but malware, tool, and intrusion-set objects,
each with `uses` relationships to techniques.

So if a signature name contains "Mimikatz", you resolve to S0002 and inherit
its technique set (T1003.001, T1558.003, etc.). Same for "Cobalt Strike",
"Emotet", "PsExec". Build an alias table from the `x_mitre_aliases` field and
match case-insensitively on normalized tokens. This is pure string lookup and
it's very high precision, because malware/tool names are rare tokens.

## Tier 2: multi-label classifier trained on the free labels

Tiers 0 and 1 hand you a labeled corpus for free — thousands of
(detection text → technique IDs) pairs from Sigma + Elastic + Splunk. Train
on it:

```python
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.pipeline import make_pipeline

vec = TfidfVectorizer(
    analyzer='char_wb', ngram_range=(3,5),   # robust to vendor mangling
    sublinear_tf=True, min_df=2
)
clf = OneVsRestClassifier(CalibratedClassifierCV(LinearSVC()))
pipe = make_pipeline(vec, clf)

mlb = MultiLabelBinarizer()
Y = mlb.fit_transform(technique_lists)
pipe.fit(texts, Y)
```

Character n-grams matter more than you'd think — signature names are full of
concatenations like `Win32/Trojan.Downloader.Gen` that word tokenizers
destroy. Train a word-level TF-IDF model too and average the probabilities;
they fail differently.

Two things that lift accuracy a lot:

1. Predict tactic first, then technique within tactic. Tactic is a 14-class
   problem and lands ~85–90%; technique is a 600+ class problem with a
   brutal long tail. A hierarchical setup lets you emit a confident tactic
   even when the technique is uncertain, and a tactic-level label is still
   operationally useful.
2. Feed more than the name. If you have the rule body — registry paths,
   process names, command-line regexes, `flow:` direction, HTTP URI
   patterns — that's far more signal than the title string.
   `\CurrentVersion\Run` is a near-deterministic T1547.001 tell.

## Tier 3: similarity fallback

For signatures the classifier abstains on, do nearest-neighbour against an
ATT&CK corpus built from each technique's name + description +
`x_mitre_detection` + procedure examples. TF-IDF cosine works; a small local
sentence encoder (`all-MiniLM-L6-v2`, 22M params, runs on CPU, no API) works
better and still costs nothing per call. Return top-5 candidates.

## Tier 4: abstain

Anything below threshold goes to an unmapped bucket with the top-5
candidates attached. A human confirms one with a click. Every confirmation
becomes training data. In a SOC, a wrong mapping is worse than a missing
one — it silently corrupts your coverage metrics and makes your ATT&CK
heatmap lie to you.

## Normalization is doing half the work

Before anything hits a model, canonicalize: strip vendor prefixes
(`ET TROJAN`, `ETPRO`, `MALWARE-CNC`), split camelCase and dots and
underscores, drop CVE IDs / IPs / hex blobs / version numbers into
placeholder tokens, lowercase, expand a hand-written abbreviation table
(`ps` → `powershell`, `lsass` → `lsass`, `uac` → `user account control`).
Cheap and it moves the numbers more than most model tuning.

## Evaluation

Hold out a stratified slice of the Sigma/Elastic corpus. Report
precision/recall per technique, not micro-averaged — micro-average hides
that you're perfect on T1059.001 and useless on the 400 techniques with
three examples each. Also measure coverage-at-precision: "what fraction can
I auto-map at ≥95% precision?" That's the number that decides how much
human review you're signing up for.

Prior art worth reading before you build: rcATT (TF-IDF + linear SVM
multi-label, exactly this approach, published with code) and MITRE's TRAM,
though TRAM's newer versions lean on transformers.

One honest caveat: the ceiling on signature-name-only mapping is lower than
people expect, because many signatures genuinely don't correspond to a
single technique — "ET POLICY Outbound DNS to Public Resolver" isn't
adversary behaviour at all. Budget for a permanent not-applicable class
rather than forcing everything into the matrix.
